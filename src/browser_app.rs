//! `sv browser`: the small AppleScript app that claims the `sv://` scheme.
//!
//! The web app opens shells on this machine with `sv://shell?…` links
//! ([`crate::deeplink`]). A browser hands such a link to whatever app
//! registered the scheme, so this module builds one: a user-owned applet in
//! `~/Applications/Svartal CLI.app` whose `open location` handler runs
//! `sv open-url` — nothing more, and no Ivaldi anywhere.
//!
//! Ownership is explicit. The app carries a marker file naming the `sv` it
//! was built for; `install` replaces only an app it recognizes, `uninstall`
//! removes only that one, and nothing here ever touches anything else in the
//! applications directories. A package manager may install the same app
//! beside its own `sv` with `--app-path`; `sv login` notices that handler
//! and leaves it to the package manager to refresh.
//!
//! Build order matters and is load-bearing: `osacompile` produces a signed
//! app, so the Info.plist edit and the marker invalidate the signature, and
//! the app is re-signed (ad-hoc, like `osacompile` itself did) before
//! LaunchServices is asked to register it.

use std::io::Write;
use std::path::{Path, PathBuf};

use crate::deeplink::shell_single_quote;
use crate::proc::ProcessRunner;

/// The app's name, and the stable identity it is re-stamped with.
pub const APP_NAME: &str = "Svartal CLI.app";
pub const BUNDLE_IDENTIFIER: &str = "com.svartal.cli";
pub const BUNDLE_NAME: &str = "Svartal CLI";
const OSACOMPILE: &str = "/usr/bin/osacompile";
const CODESIGN: &str = "/usr/bin/codesign";
const LSREGISTER: &str = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
/// The marker file, inside `Contents`, naming the `sv` this app runs.
const MARKER_FILE: &str = "svartal-cli-owned";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAppError(pub String);

impl std::fmt::Display for BrowserAppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for BrowserAppError {}

fn foreign_app(app: &Path) -> BrowserAppError {
    BrowserAppError(format!(
        "{} already exists and was not installed by sv, so sv will not touch it. Move it aside first, or pass --app-path to put the Svartal app somewhere else.",
        app.display()
    ))
}

fn io_error(what: &str, error: std::io::Error) -> BrowserAppError {
    BrowserAppError(format!("{what}: {error}"))
}

/// Where the manual install (and `sv login`) put the app: `~/Applications`.
pub fn default_app_path() -> Option<PathBuf> {
    Some(default_app_in(&PathBuf::from(std::env::var_os("HOME")?)))
}

/// The default app path under a given home, separate so a test can state the
/// home instead of the process's.
pub fn default_app_in(home: &Path) -> PathBuf {
    home.join("Applications").join(APP_NAME)
}

/// Where a package manager's `sv` has its app: two levels up from the
/// executable (`…/bin/sv` → `…/`), which is the prefix beside it — Homebrew's
/// `opt_prefix`, stable across upgrades.
pub fn package_app_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    Some(executable.parent()?.parent()?.join(APP_NAME))
}

/// The app the bare `sv browser` verbs act on, with the candidates a test
/// can state: the package handler when this `sv` has an owned one beside it
/// (a Homebrew `sv` must report and uninstall the app its formula owns, not
/// claim nothing is installed), else the user's `~/Applications` app.
pub fn resolve_default_app_from(
    package_app: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(app) = package_app
        && is_owned_handler(app)
    {
        return Some(app.to_path_buf());
    }
    home.map(default_app_in)
}

fn resolved_default_app() -> Option<PathBuf> {
    resolve_default_app_from(
        package_app_path().as_deref(),
        std::env::var_os("HOME").map(PathBuf::from).as_deref(),
    )
}

/// The `sv` the app should call, recorded at build time.
///
/// An absolute argv[0] is the best answer: `/opt/homebrew/bin/sv` is a
/// stable symlink that survives upgrades, so the app stays fresh without
/// help. A bare `sv` from `PATH` names no location, so the executable's own
/// path is the fallback — it points inside a versioned Cellar, which moves
/// on upgrade, and the freshness check in `sv login` refreshes the app.
pub fn helper_binary_path_from(invoked: &str, current_executable: Option<String>) -> String {
    if Path::new(invoked).is_absolute() {
        return invoked.to_string();
    }
    current_executable.unwrap_or_else(|| invoked.to_string())
}

pub fn helper_binary_path() -> String {
    helper_binary_path_from(
        &crate::sshproxy::invoked_binary_path(),
        std::env::current_exe()
            .ok()
            .map(|path| path.display().to_string()),
    )
}

fn contents(app: &Path) -> PathBuf {
    app.join("Contents")
}

fn marker_path(app: &Path) -> PathBuf {
    // In `Contents/Resources`, not loose in `Contents`: codesign reads a
    // stray file there as a nested code object and refuses to sign the
    // bundle, while Resources is where bundle data belongs and is sealed as
    // resources.
    contents(app).join("Resources").join(MARKER_FILE)
}

fn info_plist_path(app: &Path) -> PathBuf {
    contents(app).join("Info.plist")
}

/// The `sv` this app was built for, when the app is ours.
fn owned_marker(app: &Path) -> Option<String> {
    std::fs::read_to_string(marker_path(app))
        .ok()
        .map(|body| body.trim().to_string())
}

fn plist_has_scheme(app: &Path) -> bool {
    let Ok(plist) = std::fs::read_to_string(info_plist_path(app)) else {
        return false;
    };
    plist.contains("<key>CFBundleURLTypes</key>")
        && plist.contains(&format!("<string>{}</string>", crate::deeplink::SCHEME))
}

/// The app is there and it is ours.
pub fn is_owned_handler(app: &Path) -> bool {
    app.is_dir() && owned_marker(app).is_some() && plist_has_scheme(app)
}

/// Ours, and built for this very `sv`.
fn handler_is_fresh(app: &Path, binary: &str) -> bool {
    match owned_marker(app) {
        Some(marker) => marker == binary && Path::new(&marker).exists(),
        None => false,
    }
}

/// AppleScript string-literal quoting: backslashes and double quotes.
fn applescript_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The applet's whole script: hand an `sv://` link to the recorded `sv`.
///
/// The binary is a literal, shell-quoted at build time; the URL never is —
/// `quoted form of` quotes it at run time, and `sv open-url` parses it
/// strictly anyway. This is the only code the app runs.
pub fn handler_applescript(binary: &str) -> String {
    format!(
        "-- Installed by `sv browser install`. Hands sv:// links to the sv\n\
         -- recorded here at install time.\n\
         on open location theURL\n\
         \tdo shell script \"{sv} open-url \" & quoted form of theURL\n\
         end open location\n",
        sv = applescript_string(&shell_single_quote(binary)),
    )
}

/// Set a `<key>`'s `<string>` value in an XML plist, inserting the pair when
/// the key is absent.
fn set_plist_string(plist: &str, key: &str, value: &str) -> Result<String, BrowserAppError> {
    let key_tag = format!("<key>{key}</key>");
    if let Some(key_at) = plist.find(&key_tag) {
        let value_at = plist[key_at..]
            .find("<string>")
            .map(|offset| key_at + offset)
            .ok_or_else(|| {
                BrowserAppError(format!("the app's Info.plist has a {key} with no value."))
            })?;
        let value_end = plist[value_at..]
            .find("</string>")
            .map(|offset| value_at + offset + "</string>".len())
            .ok_or_else(|| {
                BrowserAppError(format!("the app's Info.plist has a {key} with no value."))
            })?;
        return Ok(format!(
            "{}<string>{value}</string>{}",
            &plist[..value_at],
            &plist[value_end..]
        ));
    }
    let Some(end) = plist.rfind("</dict>") else {
        return Err(BrowserAppError(
            "the app's Info.plist has no dictionary to add to.".to_string(),
        ));
    };
    Ok(format!(
        "{}\t{key_tag}\n\t<string>{value}</string>\n{}",
        &plist[..end],
        &plist[end..]
    ))
}

/// Rewrite `osacompile`'s Info.plist into the Svartal handler's.
///
/// osacompile stamps its own throwaway identity on the applet; a handler
/// that LaunchServices is expected to keep finding across reinstallations
/// and upgrades needs a stable one (`CFBundleIdentifier`, `CFBundleName`).
/// `LSUIElement` keeps a stray double-click from parking an icon in the
/// Dock. All of it before the re-sign, so the signature covers it.
pub fn customize_plist(plist: &str) -> Result<String, BrowserAppError> {
    if plist.contains("<key>CFBundleURLTypes</key>") {
        return Err(BrowserAppError(
            "the app's Info.plist already claims a URL scheme, which a fresh compile should not."
                .to_string(),
        ));
    }
    let Some(_) = plist.rfind("</dict>") else {
        return Err(BrowserAppError(
            "the app's Info.plist has no dictionary to add to.".to_string(),
        ));
    };
    let mut additions = format!(
        "\t<key>CFBundleURLTypes</key>\n\
         \t<array>\n\
         \t\t<dict>\n\
         \t\t\t<key>CFBundleURLName</key>\n\
         \t\t\t<string>{BUNDLE_IDENTIFIER}</string>\n\
         \t\t\t<key>CFBundleURLSchemes</key>\n\
         \t\t\t<array>\n\
         \t\t\t\t<string>{}</string>\n\
         \t\t\t</array>\n\
         \t\t</dict>\n\
         \t</array>\n",
        crate::deeplink::SCHEME,
    );
    if !plist.contains("<key>LSUIElement</key>") {
        additions.push_str("\t<key>LSUIElement</key>\n\t<true/>\n");
    }
    let claimed = set_plist_string(plist, "CFBundleIdentifier", BUNDLE_IDENTIFIER)?;
    let named = set_plist_string(&claimed, "CFBundleName", BUNDLE_NAME)?;
    let Some(end) = named.rfind("</dict>") else {
        return Err(BrowserAppError(
            "the app's Info.plist has no dictionary to add to.".to_string(),
        ));
    };
    Ok(format!("{}{additions}{}", &named[..end], &named[end..]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallChange {
    Created,
    Replaced,
}

/// Compile and register the handler app at `app`, calling `binary`.
///
/// `install` is also the update: an owned app is replaced, a foreign one is
/// refused, and nothing outside `app` is touched. A failure anywhere after
/// the compile removes the half-built app again, so `install` leaves either
/// a complete handler or none.
pub fn install(
    runner: &dyn ProcessRunner,
    app: &Path,
    binary: &str,
) -> Result<InstallChange, BrowserAppError> {
    let change = if app.is_dir() {
        if owned_marker(app).is_none() {
            return Err(foreign_app(app));
        }
        std::fs::remove_dir_all(app)
            .map_err(|error| io_error("could not replace the old app", error))?;
        InstallChange::Replaced
    } else {
        InstallChange::Created
    };
    install_fresh(runner, app, binary).map(|()| change)
}

fn install_fresh(
    runner: &dyn ProcessRunner,
    app: &Path,
    binary: &str,
) -> Result<(), BrowserAppError> {
    let built = |step: &str| {
        BrowserAppError(format!(
            "could not {step} the Svartal app at {}",
            app.display()
        ))
    };
    let give_up = |error: BrowserAppError| {
        let _ = std::fs::remove_dir_all(app);
        error
    };
    if let Some(parent) = app.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| io_error("could not create the applications directory", error))?;
    }
    // The source lives in the system temporary directory, not in HOME: a
    // package manager's sandbox may write neither HOME nor the app's final
    // neighbours, and it always may write here.
    let suffix = crate::fsutil::random_suffix()
        .map_err(|error| BrowserAppError(format!("could not name a temporary file: {error}")))?;
    let source = std::env::temp_dir().join(format!("sv-browser-app-{suffix}.applescript"));
    let cleanup_source = |source: &Path| {
        let _ = std::fs::remove_file(source);
    };
    std::fs::write(&source, handler_applescript(binary))
        .map_err(|error| io_error("could not write the AppleScript source", error))?;
    let app_text = app.display().to_string();
    let source_text = source.display().to_string();
    let compiled = runner.run(OSACOMPILE, &["-o", &app_text, &source_text]);
    cleanup_source(&source);
    let compiled = compiled.map_err(|detail| give_up(built(&format!("compile ({detail})"))))?;
    if !compiled.success {
        let detail = if compiled.stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", compiled.stderr)
        };
        return Err(give_up(BrowserAppError(format!(
            "osacompile could not build the Svartal app at {app_text}{detail}"
        ))));
    }

    // Claim the scheme and stamp the stable identity — both before the
    // re-sign, so the signature covers everything the app ends up carrying.
    let plist_path = info_plist_path(app);
    let plist = std::fs::read_to_string(&plist_path)
        .map_err(|error| give_up(io_error("could not read the new app's Info.plist", error)))?;
    let edited = customize_plist(&plist).map_err(|error| {
        give_up(BrowserAppError(format!(
            "could not claim the sv scheme: {}",
            error.0
        )))
    })?;
    std::fs::write(&plist_path, edited)
        .map_err(|error| give_up(io_error("could not write the new app's Info.plist", error)))?;
    std::fs::create_dir_all(contents(app).join("Resources")).map_err(|error| {
        give_up(io_error(
            "could not create the app's Resources directory",
            error,
        ))
    })?;
    std::fs::write(marker_path(app), format!("{binary}\n"))
        .map_err(|error| give_up(io_error("could not mark the app as sv's", error)))?;

    // osacompile's signature stopped matching the moment the bundle changed;
    // re-sign ad-hoc, exactly as osacompile did, or LaunchServices will be
    // handing out an app macOS refuses to run.
    let signed = runner.run(CODESIGN, &["--force", "--sign", "-", &app_text]);
    let signed = signed.map_err(|detail| give_up(built(&format!("re-sign ({detail})"))))?;
    if !signed.success {
        let detail = if signed.stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", signed.stderr)
        };
        return Err(give_up(BrowserAppError(format!(
            "codesign could not re-sign the Svartal app at {app_text}{detail}"
        ))));
    }
    let registered = runner
        .run(LSREGISTER, &["-f", &app_text])
        .map_err(|detail| give_up(built(&format!("register ({detail})"))))?;
    if !registered.success {
        let detail = if registered.stderr.is_empty() {
            String::new()
        } else {
            format!(": {}", registered.stderr)
        };
        // The app is complete and owned on disk; removing it would be worse
        // than leaving it, so this says how to finish the job instead.
        return Err(BrowserAppError(format!(
            "the Svartal app is in place at {app_text} but macOS did not register it{detail}. Run `sv browser install` again."
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UninstallChange {
    Removed { note: Option<String> },
    NotInstalled,
}

/// Remove the handler app — ours only, and nothing but it.
pub fn uninstall(
    runner: &dyn ProcessRunner,
    app: &Path,
) -> Result<UninstallChange, BrowserAppError> {
    if !app.is_dir() {
        return Ok(UninstallChange::NotInstalled);
    }
    if owned_marker(app).is_none() {
        return Err(foreign_app(app));
    }
    // Unregister first, and best effort: a LaunchServices that will not
    // forget the app should not keep the app either.
    let note = match runner.run(LSREGISTER, &["-u", &app.display().to_string()]) {
        Ok(output) if output.success => None,
        Ok(output) => Some(format!(
            "macOS may still remember the app for sv:// links{}. Open it once to see, or run `sv browser install` and uninstall again.",
            if output.stderr.is_empty() {
                String::from(".")
            } else {
                format!(": {}", output.stderr)
            }
        )),
        Err(detail) => Some(format!(
            "macOS could not be asked to forget the app ({detail})."
        )),
    };
    std::fs::remove_dir_all(app).map_err(|error| io_error("could not remove the app", error))?;
    Ok(UninstallChange::Removed { note })
}

/// `sv browser status`: what is on disk, from evidence on disk. LaunchServices'
/// own database is not queried — the app, its marker and its Info.plist are
/// the facts this CLI put there and can vouch for.
pub fn status(out: &mut dyn Write, app: &Path) -> Result<(), BrowserAppError> {
    if !app.is_dir() {
        writeln!(
            out,
            "The Svartal app is not installed at {}. Run `sv browser install` so sv:// links open a Terminal.",
            app.display()
        )
        .ok();
        return Ok(());
    }
    writeln!(out, "The Svartal app is at {}.", app.display()).ok();
    match owned_marker(app) {
        Some(marker) => {
            if Path::new(&marker).exists() {
                writeln!(out, "It opens sv:// links with {marker}.").ok();
            } else {
                writeln!(
                    out,
                    "It was built for {marker}, which is not there anymore. Run `sv browser install` to refresh it."
                )
                .ok();
            }
        }
        None => {
            writeln!(
                out,
                "It was not installed by sv, so sv will not touch it. `sv browser install` refuses it; remove it by hand first."
            )
            .ok();
        }
    }
    if plist_has_scheme(app) {
        writeln!(out, "Its Info.plist claims the sv scheme.").ok();
    } else {
        writeln!(
            out,
            "Its Info.plist does not claim the sv scheme. Run `sv browser install` again."
        )
        .ok();
    }
    Ok(())
}

/// `sv browser install|status|uninstall [--app-path <absolute .app path>]`.
///
/// With `--app-path` no HOME is read: a package manager's post-install step
/// names where the app goes and the sandbox it runs in may not look at the
/// user's home at all. Without it, the verbs act on the app this `sv` uses:
/// the package manager's when there is an owned one beside the executable,
/// else the user's.
pub fn browser_command(
    out: &mut dyn Write,
    verb: Option<&str>,
    app_path: Option<&str>,
) -> Result<(), BrowserAppError> {
    if !cfg!(target_os = "macos") {
        return Err(BrowserAppError(
            "The Svartal app that handles sv:// links is a macOS feature; there is nothing to install here.".to_string(),
        ));
    }
    let app = match app_path {
        Some(path) => {
            let path = Path::new(path);
            if !path.is_absolute() || path.extension().is_none_or(|extension| extension != "app") {
                return Err(BrowserAppError(
                    "--app-path needs an absolute path to the .app bundle, like /opt/homebrew/opt/svartal-cli/Svartal CLI.app.".to_string(),
                ));
            }
            path.to_path_buf()
        }
        None => resolved_default_app().ok_or_else(|| {
            BrowserAppError("this account has no home directory, so there is nowhere for the default Svartal app. Pass --app-path.".to_string())
        })?,
    };
    let runner = crate::proc::SystemRunner;
    match verb {
        Some("install") => {
            let binary = helper_binary_path();
            match install(&runner, &app, &binary)? {
                InstallChange::Created => writeln!(
                    out,
                    "Installed the Svartal app at {}. sv:// links now open a Terminal running {binary}.",
                    app.display()
                ),
                InstallChange::Replaced => writeln!(
                    out,
                    "Updated the Svartal app at {}. sv:// links now open a Terminal running {binary}.",
                    app.display()
                ),
            }
            .ok();
        }
        Some("status") => status(out, &app)?,
        Some("uninstall") => match uninstall(&runner, &app)? {
            UninstallChange::Removed { note } => {
                writeln!(out, "Removed the Svartal app at {}.", app.display()).ok();
                if let Some(note) = note {
                    writeln!(out, "{note}").ok();
                }
            }
            UninstallChange::NotInstalled => {
                writeln!(out, "There was no Svartal app at {}.", app.display()).ok();
            }
        },
        Some(other) => {
            return Err(BrowserAppError(format!(
                "`sv browser {other}` is not a thing sv can do. It is `sv browser install`, `sv browser status` or `sv browser uninstall`."
            )));
        }
        None => {
            return Err(BrowserAppError(
                "`sv browser` needs one of: install, status, uninstall.".to_string(),
            ));
        }
    }
    Ok(())
}

/// After a successful interactive `sv login`, make sure `sv://` links reach
/// this `sv`. Best effort: the worst outcome is a warning, never a failed
/// login and never extra setup the person has to paste.
///
/// A package manager may already have installed a handler beside this `sv`
/// (`…/bin/sv` → `…/Svartal CLI.app`); that one is refreshed by the same
/// package manager on upgrade, so this leaves it strictly alone rather than
/// install a second app to compete with it.
pub fn ensure_registered_after_login(out: &mut dyn Write) {
    if !cfg!(target_os = "macos") {
        return;
    }
    if let Some(package_app) = package_app_path()
        && is_owned_handler(&package_app)
    {
        return;
    }
    let Some(app) = default_app_path() else {
        return;
    };
    let binary = helper_binary_path();
    if handler_is_fresh(&app, &binary) {
        return;
    }
    match install(&crate::proc::SystemRunner, &app, &binary) {
        Ok(_) => {
            writeln!(
                out,
                "sv:// links from the Svartal web app now open a Terminal on this Mac. `sv browser uninstall` takes it back."
            )
            .ok();
        }
        Err(error) => {
            writeln!(
                out,
                "sv:// links will not open a Terminal on this Mac yet: {}. Run `sv browser install` to try again.",
                error.0
            )
            .ok();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>CFBundleName</key>
\t<string>applet</string>
\t<key>CFBundleExecutable</key>
\t<string>applet</string>
\t<key>CFBundleIdentifier</key>
\t<string>com.example.fresh-compile</string>
</dict>
</plist>
";

    #[test]
    fn the_handler_hands_links_to_the_recorded_sv_and_quotes_them() {
        let script = handler_applescript("/opt/homebrew/bin/sv");
        assert!(
            script.contains(
                "do shell script \"'/opt/homebrew/bin/sv' open-url \" & quoted form of theURL"
            ),
            "{script}"
        );
        assert!(script.contains("on open location theURL"));
        // A binary with an apostrophe is single-quoted for the shell and
        // escaped for the AppleScript string both, so the .applescript text
        // carries the shell escape's backslash doubled.
        let awkward = handler_applescript("/opt/Marc's Tools/sv runner");
        assert!(
            awkward.contains("do shell script \"'/opt/Marc'\\\\''s Tools/sv runner' open-url \" & quoted form of theURL"),
            "{awkward}"
        );
        // The URL is never a literal in the script.
        assert!(!script.contains("environmentId"));
    }

    #[test]
    fn the_plist_gets_a_stable_identity_a_dock_shield_and_the_scheme_claim() {
        let edited = customize_plist(SAMPLE_PLIST).expect("customized");
        // The scheme claim...
        assert!(edited.contains("<key>CFBundleURLTypes</key>"));
        assert!(edited.contains("<string>com.svartal.cli</string>"));
        assert!(edited.contains("<string>sv</string>"));
        // ...and the stable identity, replacing osacompile's throwaway one.
        assert!(!edited.contains("com.example.fresh-compile"), "{edited}");
        assert!(
            edited.contains("<key>CFBundleIdentifier</key>\n\t<string>com.svartal.cli</string>")
        );
        assert!(edited.contains("<key>CFBundleName</key>\n\t<string>Svartal CLI</string>"));
        // No Dock icon for a background handler.
        assert!(edited.contains("<key>LSUIElement</key>\n\t<true/>"));
        assert!(edited.trim_end().ends_with("</dict>\n</plist>"));
        // Refuses to double-claim.
        assert!(customize_plist(&edited).is_err());
        assert!(customize_plist("not a plist").is_err());
    }

    #[test]
    fn the_helper_prefers_a_stable_absolute_path() {
        // An absolute argv[0] — Homebrew's opt symlink — is used as-is.
        assert_eq!(
            helper_binary_path_from("/opt/homebrew/bin/sv", Some("/nowhere/sv".to_string())),
            "/opt/homebrew/bin/sv"
        );
        // A bare word off PATH names no location: fall back to the executable.
        assert_eq!(
            helper_binary_path_from(
                "sv",
                Some("/opt/homebrew/Cellar/svartal-cli/0.1.12/bin/sv".to_string())
            ),
            "/opt/homebrew/Cellar/svartal-cli/0.1.12/bin/sv"
        );
        // With nothing better, the word itself.
        assert_eq!(helper_binary_path_from("sv", None), "sv");
    }

    #[test]
    fn the_default_app_lives_in_the_user_applications_directory() {
        let home = Path::new("/Users/example");
        assert_eq!(
            default_app_in(home),
            home.join("Applications/Svartal CLI.app")
        );
    }

    #[test]
    fn the_default_prefers_an_owned_package_handler_over_the_users_app() {
        let root = std::env::temp_dir().join(format!(
            "sv-browser-resolve-{}-{}",
            std::process::id(),
            crate::fsutil::random_suffix().expect("a suffix")
        ));
        std::fs::create_dir_all(&root).expect("scratch directory");
        let owned_package = root.join("owned/Svartal CLI.app");
        make_owned_app_for_test(&owned_package, "/opt/homebrew/bin/sv");
        let foreign_package = root.join("foreign/Svartal CLI.app");
        std::fs::create_dir_all(foreign_package.join("Contents/MacOS")).expect("bundle");
        let home = root.join("home");
        let user_app = home.join("Applications/Svartal CLI.app");

        // An owned package handler wins...
        assert_eq!(
            resolve_default_app_from(Some(&owned_package), Some(&home)),
            Some(owned_package.clone())
        );
        // ...a package app that is not ours does not...
        assert_eq!(
            resolve_default_app_from(Some(&foreign_package), Some(&home)),
            Some(user_app.clone())
        );
        // ...and with no package app at all, the user's app is the answer.
        assert_eq!(resolve_default_app_from(None, Some(&home)), Some(user_app));
        assert_eq!(resolve_default_app_from(None, None), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A bundle with the two facts `is_owned_handler` reads: the marker and
    /// the Info.plist scheme claim.
    fn make_owned_app_for_test(app: &Path, binary: &str) {
        std::fs::create_dir_all(marker_path(app).parent().expect("Resources")).expect("bundle");
        let plist = customize_plist(SAMPLE_PLIST).expect("customized");
        std::fs::write(info_plist_path(app), plist).expect("Info.plist");
        std::fs::write(marker_path(app), format!("{binary}\n")).expect("marker");
    }
}
