//! `sv browser` and `sv open-url`: the sv:// half of the CLI, with the
//! system's tools answered by a recording fake.
//!
//! What the fake stands in for is everything that would touch the real
//! machine — `osacompile` (it builds a bundle skeleton shaped like the real
//! one), `codesign`, `lsregister`, `open` — so no test here registers
//! anything, signs anything, or opens a Terminal. What the tests pin is what
//! would hurt: only an app sv owns is ever replaced or removed, the bundle
//! is re-signed after its plist changes and before registration, a failed
//! build leaves nothing behind, and the `.command` a link writes really does
//! leave its own directory, delete it, and hand the window to one command:
//! `sv shell <id>`.

mod common;

use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use common::TempDir;
use svartal::browser_app::{
    self, InstallChange, UninstallChange, is_owned_handler, status as app_status,
};
use svartal::deeplink;
use svartal::proc::{ProcessOutput, ProcessRunner};

/// What `osacompile` writes, minus everything this CLI does not rely on.
const OSACOMPILED_PLIST: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>CFBundleName</key>
\t<string>Svartal CLI</string>
\t<key>CFBundleExecutable</key>
\t<string>applet</string>
\t<key>CFBundleIdentifier</key>
\t<string>com.example.fresh-compile</string>
</dict>
</plist>
";

fn write_foreign_app(app: &Path) {
    std::fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle directories");
    std::fs::write(app.join("Contents/Info.plist"), OSACOMPILED_PLIST).expect("Info.plist");
    std::fs::write(app.join("Contents/MacOS/applet"), b"#!/bin/sh\n").expect("applet");
}

/// Records every call, answers like the real tools would, and can be told
/// to fail one of them.
struct FakeRunner {
    calls: Mutex<Vec<(String, Vec<String>)>>,
    failures: Mutex<std::collections::BTreeMap<String, String>>,
}

impl FakeRunner {
    fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            failures: Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Make the tool named by its program's file stem fail with `detail`.
    fn fail(&self, tool: &str, detail: &str) {
        self.failures
            .lock()
            .unwrap()
            .insert(tool.to_string(), detail.to_string());
    }

    fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }

    /// The argument lists the given tool was called with, in order.
    fn calls_for(&self, tool: &str) -> Vec<Vec<String>> {
        self.calls()
            .into_iter()
            .filter(|(program, _)| {
                Path::new(program)
                    .file_stem()
                    .is_some_and(|stem| stem == tool)
            })
            .map(|(_, args)| args)
            .collect()
    }

    fn programs(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .map(|(program, _)| {
                Path::new(&program)
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// The bundle `osacompile` would have left at the `-o` path.
    fn compile_like_osacompile(&self, args: &[String]) {
        let Some(output) = args
            .iter()
            .position(|argument| argument == "-o")
            .map(|index| &args[index + 1])
        else {
            return;
        };
        let app = PathBuf::from(output);
        std::fs::create_dir_all(app.join("Contents/MacOS")).expect("bundle directories");
        std::fs::write(app.join("Contents/Info.plist"), OSACOMPILED_PLIST).expect("Info.plist");
        std::fs::write(app.join("Contents/MacOS/applet"), b"#!/bin/sh\n").expect("applet");
    }
}

impl ProcessRunner for FakeRunner {
    fn run(&self, program: &str, args: &[&str]) -> Result<ProcessOutput, String> {
        self.calls.lock().unwrap().push((
            program.to_string(),
            args.iter().map(|argument| argument.to_string()).collect(),
        ));
        let tool = Path::new(program)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if let Some(detail) = self.failures.lock().unwrap().get(&tool) {
            return Ok(ProcessOutput::failed(detail));
        }
        if tool == "osacompile" {
            let args = self
                .calls
                .lock()
                .unwrap()
                .last()
                .cloned()
                .unwrap_or_default();
            self.compile_like_osacompile(&args.1);
        }
        Ok(ProcessOutput::succeeded())
    }
}

fn marker_of(app: &Path) -> String {
    // In Contents/Resources: a file loose in Contents reads as a nested code
    // object to codesign, which then refuses to sign the bundle.
    std::fs::read_to_string(app.join("Contents/Resources/svartal-cli-owned"))
        .expect("the ownership marker")
        .trim()
        .to_string()
}

// -- install ---------------------------------------------------------------

#[test]
fn install_builds_claims_signs_and_registers_in_that_order() {
    let root = TempDir::new("browser-install");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();

    assert_eq!(
        browser_app::install(&runner, &app, "/opt/homebrew/bin/sv"),
        Ok(InstallChange::Created)
    );

    // The order is the security property: compile, change the bundle, then
    // re-sign it, then hand it to LaunchServices.
    assert_eq!(runner.programs(), ["osacompile", "codesign", "lsregister"]);

    // osacompile got the app and a source file in the system temporary
    // directory, and the source did not survive the call.
    let compile = runner.calls_for("osacompile")[0].clone();
    assert_eq!(compile[0], "-o");
    assert_eq!(Path::new(&compile[1]), app.as_path());
    assert!(Path::new(&compile[2]).starts_with(std::env::temp_dir()));
    assert!(!Path::new(&compile[2]).exists());

    assert_eq!(
        runner.calls_for("codesign")[0],
        vec![
            "--force".to_string(),
            "--sign".to_string(),
            "-".to_string(),
            app.display().to_string()
        ]
    );
    assert_eq!(
        runner.calls_for("lsregister")[0],
        vec!["-f".to_string(), app.display().to_string()]
    );

    // The bundle carries the stable identity and claims the scheme, and it
    // names the sv it runs.
    let plist = std::fs::read_to_string(app.join("Contents/Info.plist")).expect("Info.plist");
    assert!(plist.contains("<key>CFBundleURLTypes</key>"));
    assert!(plist.contains("<string>sv</string>"));
    assert!(plist.contains("<key>CFBundleIdentifier</key>\n\t<string>com.svartal.cli</string>"));
    assert!(!plist.contains("com.example.fresh-compile"));
    // The marker lives in Resources, where codesign seals it as a resource
    // instead of reading it as a nested code object.
    assert!(app.join("Contents/Resources/svartal-cli-owned").is_file());
    assert_eq!(marker_of(&app), "/opt/homebrew/bin/sv");
    assert!(is_owned_handler(&app));
}

#[test]
fn install_replaces_an_owned_app_and_updates_the_sv_it_names() {
    let root = TempDir::new("browser-update");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();
    browser_app::install(
        &runner,
        &app,
        "/opt/homebrew/Cellar/svartal-cli/0.1.12/bin/sv",
    )
    .expect("first install");

    assert_eq!(
        browser_app::install(&runner, &app, "/opt/homebrew/bin/sv"),
        Ok(InstallChange::Replaced)
    );
    assert_eq!(marker_of(&app), "/opt/homebrew/bin/sv");
    assert!(is_owned_handler(&app));
    // Every install registers what it built: two full runs, not one and a
    // stale bundle.
    assert_eq!(runner.calls_for("osacompile").len(), 2);
    assert_eq!(runner.calls_for("codesign").len(), 2);
    assert_eq!(runner.calls_for("lsregister").len(), 2);
}

#[test]
fn install_refuses_an_app_it_does_not_own() {
    let root = TempDir::new("browser-foreign");
    let app = root.path().join("Svartal CLI.app");
    write_foreign_app(&app);
    let runner = FakeRunner::new();

    let error = browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect_err("refused");
    assert!(error.0.contains("was not installed by sv"), "{error}");
    // Untouched, and nothing was run.
    assert_eq!(
        std::fs::read_to_string(app.join("Contents/Info.plist")).expect("Info.plist"),
        OSACOMPILED_PLIST
    );
    assert!(runner.calls().is_empty());
}

#[test]
fn a_failed_signing_leaves_no_half_built_app_behind() {
    let root = TempDir::new("browser-sign-fail");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();
    runner.fail("codesign", "code object is not signed");

    let error = browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect_err("refused");
    assert!(error.0.contains("re-sign"), "{error}");
    assert!(error.0.contains("code object is not signed"), "{error}");
    assert!(!app.exists(), "the failed bundle was cleaned up");
    // The compile source is gone too, failure or not.
    let compile = runner.calls_for("osacompile")[0].clone();
    assert!(!Path::new(&compile[2]).exists());
}

#[test]
fn a_failed_compile_leaves_nothing_behind() {
    let root = TempDir::new("browser-compile-fail");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();
    runner.fail("osacompile", "syntax error");

    let error = browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect_err("refused");
    assert!(error.0.contains("osacompile"), "{error}");
    assert!(error.0.contains("syntax error"), "{error}");
    assert!(!app.exists());
}

#[test]
fn a_failed_registration_keeps_the_finished_app() {
    let root = TempDir::new("browser-register-fail");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();
    runner.fail("lsregister", "LaunchServices is unhappy");

    let error = browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect_err("refused");
    assert!(error.0.contains("did not register it"), "{error}");
    assert!(
        error.0.contains("Run `sv browser install` again"),
        "{error}"
    );
    // The app is complete and owned on disk; the error says how to finish.
    assert!(is_owned_handler(&app));
}

// -- uninstall -------------------------------------------------------------

#[test]
fn uninstall_removes_the_owned_app_and_nothing_else() {
    let root = TempDir::new("browser-uninstall");
    let app = root.path().join("Svartal CLI.app");
    let neighbour = root.path().join("Other.app");
    let runner = FakeRunner::new();
    browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect("installed");
    write_foreign_app(&neighbour);

    assert_eq!(
        browser_app::uninstall(&runner, &app),
        Ok(UninstallChange::Removed { note: None })
    );
    assert!(!app.exists());
    // The neighbour, and the directory both lived in, are still there.
    assert!(neighbour.join("Contents/Info.plist").is_file());
    assert!(root.path().is_dir());
    // The install registered with `-f`; the unregistration is its own call.
    assert_eq!(
        runner.calls_for("lsregister")[1],
        vec!["-u".to_string(), app.display().to_string()]
    );
}

#[test]
fn uninstall_refuses_an_app_it_does_not_own() {
    let root = TempDir::new("browser-uninstall-foreign");
    let app = root.path().join("Svartal CLI.app");
    write_foreign_app(&app);
    let runner = FakeRunner::new();

    let error = browser_app::uninstall(&runner, &app).expect_err("refused");
    assert!(error.0.contains("was not installed by sv"), "{error}");
    assert!(app.join("Contents/Info.plist").is_file());
}

#[test]
fn uninstalling_what_is_not_there_is_not_an_error() {
    let root = TempDir::new("browser-uninstall-empty");
    let runner = FakeRunner::new();
    assert_eq!(
        browser_app::uninstall(&runner, &root.path().join("Svartal CLI.app")),
        Ok(UninstallChange::NotInstalled)
    );
}

// -- status ----------------------------------------------------------------

/// `sv browser status` for one app, as text.
fn report_of(app: &Path) -> String {
    let mut buffer = Vec::new();
    app_status(&mut buffer, app).expect("status");
    String::from_utf8(buffer).expect("text")
}

#[test]
fn status_reports_an_installed_app_from_its_own_evidence() {
    let root = TempDir::new("browser-status");
    let app = root.path().join("Svartal CLI.app");
    let runner = FakeRunner::new();
    browser_app::install(&runner, &app, "/opt/homebrew/bin/sv").expect("installed");

    let report = report_of(&app);
    assert!(report.contains("The Svartal app is at"), "{report}");
    assert!(
        report.contains("opens sv:// links with /opt/homebrew/bin/sv"),
        "{report}"
    );
    assert!(report.contains("claims the sv scheme"), "{report}");

    // A marker naming an sv that is gone says so.
    std::fs::write(
        app.join("Contents/Resources/svartal-cli-owned"),
        "/gone/sv\n",
    )
    .expect("marker");
    let report = report_of(&app);
    assert!(report.contains("is not there anymore"), "{report}");
}

#[test]
fn status_reports_a_missing_or_foreign_app() {
    let root = TempDir::new("browser-status-missing");
    let report = report_of(&root.path().join("Svartal CLI.app"));
    assert!(report.contains("is not installed at"), "{report}");

    let foreign = root.path().join("Svartal CLI.app");
    write_foreign_app(&foreign);
    let report = report_of(&foreign);
    assert!(report.contains("was not installed by sv"), "{report}");
}

// -- the command surface -----------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn browser_command_validates_before_touching_anything() {
    // These paths stop before any system tool is run.
    let mut out = Vec::new();

    let error =
        browser_app::browser_command(&mut out, Some("dance"), None).expect_err("unknown verb");
    assert!(
        error.0.contains("`sv browser dance` is not a thing"),
        "{error}"
    );
    let error = browser_app::browser_command(&mut out, None, None).expect_err("no verb");
    assert!(
        error.0.contains("needs one of: install, status, uninstall"),
        "{error}"
    );
    let error = browser_app::browser_command(&mut out, Some("install"), Some("relative/App.app"))
        .expect_err("relative path");
    assert!(error.0.contains("absolute"), "{error}");
    let error = browser_app::browser_command(
        &mut out,
        Some("install"),
        Some("/opt/homebrew/opt/svartal-cli"),
    )
    .expect_err("not an .app bundle");
    assert!(error.0.contains(".app bundle"), "{error}");
}

#[test]
fn open_url_refuses_links_that_are_not_shell_links() {
    // The parse happens before anything is touched, on every platform.
    let mut out = Vec::new();
    let error =
        deeplink::open_url_command(&mut out, "https://svartal.com/open?environmentId=env-1")
            .expect_err("not a shell link");
    assert!(error.0.contains("is not a Svartal shell link"), "{error}");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn open_url_is_explicitly_macos_only() {
    let mut out = Vec::new();
    let error = deeplink::open_url_command(&mut out, "sv://shell?environmentId=env-1")
        .expect_err("unsupported");
    assert!(error.0.contains("macOS feature"), "{error}");
    assert!(error.0.contains("sv shell env-1"), "{error}");

    let error = browser_app::browser_command(&mut Vec::new(), Some("install"), None)
        .expect_err("unsupported");
    assert!(error.0.contains("macOS feature"), "{error}");
}

// -- the .command a link runs ----------------------------------------------

#[test]
fn opening_a_link_asks_terminal_to_run_a_private_script() {
    let runner = FakeRunner::new();
    let link = deeplink::parse_shell_link("sv://shell?environmentId=env-1").expect("a shell link");
    deeplink::open_link_in_terminal(&runner, &link, "/opt/homebrew/bin/sv").expect("opened");

    let opens = runner.calls_for("open");
    assert_eq!(opens.len(), 1, "one open, one window");
    assert_eq!(opens[0][0], "-a");
    assert_eq!(opens[0][1], "Terminal");

    let script = PathBuf::from(&opens[0][2]);
    let directory = script
        .parent()
        .expect("the script's directory")
        .to_path_buf();
    assert!(directory.starts_with(std::env::temp_dir()));
    assert!(
        directory
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("sv-open-shell-"))
    );
    assert_eq!(
        std::fs::metadata(&script).expect("the script").mode() & 0o777,
        0o700
    );
    assert_eq!(
        std::fs::metadata(&directory).expect("the directory").mode() & 0o777,
        0o700
    );
    let body = std::fs::read_to_string(&script).expect("the script");
    assert!(
        body.contains("exec '/opt/homebrew/bin/sv' shell 'env-1'"),
        "{body}"
    );

    // The test's runner does not run the script, so clean up by hand; the
    // real one deletes itself, and the next test proves that.
    std::fs::remove_dir_all(&directory).expect("test cleanup");
}

#[test]
fn an_open_macos_refuses_leaves_no_script_behind() {
    let runner = FakeRunner::new();
    runner.fail("open", "no such application");
    let link = deeplink::parse_shell_link("sv://shell?environmentId=env-1").expect("a shell link");

    let error = deeplink::open_link_in_terminal(&runner, &link, "/opt/homebrew/bin/sv")
        .expect_err("refused");
    assert!(error.0.contains("no such application"), "{error}");

    let script = PathBuf::from(&runner.calls_for("open")[0][2]);
    assert!(!script.exists());
    assert!(!script.parent().expect("the directory").exists());
}

/// The script, run for real — with a recording `sv`, not the real one, and
/// from `/bin/sh`, not Terminal. What it proves is the whole point of the
/// file: it works from its own directory (which it then deletes), and the
/// only command it ever runs is `sv shell <id>` with a path that no link
/// chose.
#[test]
fn the_command_script_leaves_home_and_hands_the_terminal_to_sv() {
    let root = TempDir::new("command-script");
    // A recording sv, at a path with a space and an apostrophe.
    let tools = root.path().join("Marc's Tools");
    std::fs::create_dir_all(&tools).expect("tools directory");
    let sv = tools.join("sv runner");
    let recording = root.path().join("invocation.txt");
    std::fs::write(
        &sv,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$PWD\" \"$@\" > {}\n",
            deeplink::shell_single_quote(&recording.display().to_string())
        ),
    )
    .expect("the recording sv");
    std::fs::set_permissions(&sv, std::fs::Permissions::from_mode(0o755)).expect("runnable");

    let directory = root.path().join("sv-open-shell-run");
    std::fs::create_dir(&directory).expect("the script's directory");
    let script = deeplink::write_open_command(&directory, "env-1", &sv.display().to_string())
        .expect("script");

    // Terminal starts a .command in the script's own directory; so does this.
    let status = Command::new("/bin/sh")
        .arg(&script)
        .current_dir(&directory)
        .status()
        .expect("run");
    assert!(status.success());

    // The script and its directory are gone...
    assert!(!script.exists());
    assert!(!directory.exists());
    // ...and sv ran from the home it moved to first, with the one command.
    let recorded = std::fs::read_to_string(&recording).expect("the recording");
    let lines: Vec<&str> = recorded.lines().collect();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".to_string());
    assert_eq!(
        lines[0], home,
        "sv ran from the script's new cwd, not the deleted one"
    );
    assert!(Path::new(&home).exists());
    assert_eq!(lines[1], "shell");
    assert_eq!(lines[2], "env-1");
}
