//! The `sv://` link contract, and the macOS half of honoring one.
//!
//! The web app opens a shell on the person's machine with
//! `sv://shell?environmentId=<id>`. The link is the whole contract: it names
//! an environment and carries nothing else — no command, no origin, no
//! token — so the only thing this module does with one is turn it back into
//! `sv shell <id>`, the command a person could have typed.
//!
//! On macOS the Terminal appears through a one-shot `.command` file in a
//! `0700` directory: `/usr/bin/open -a Terminal` runs it, and the script
//! deletes the file and its directory before handing the window to `sv`.
//! Off macOS `sv open-url` says the feature is macOS-only and points at
//! `sv shell`.

use std::io::Write;
use std::path::{Path, PathBuf};

use url::Url;

use crate::proc::ProcessRunner;

pub const SCHEME: &str = "sv";
pub const SHELL_HOST: &str = "shell";
pub const ENVIRONMENT_ID_PARAMETER: &str = "environmentId";
pub const OPEN_PROGRAM: &str = "/usr/bin/open";
pub const TERMINAL_APP: &str = "Terminal";
/// `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`: one lead character plus 127 more.
const MAXIMUM_ID_CHARACTERS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeepLinkError(pub String);

impl std::fmt::Display for DeepLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for DeepLinkError {}

const NOT_A_SHELL_LINK: &str = "That is not a Svartal shell link. A shell link looks like sv://shell?environmentId=<id>, with the id of one of your workspaces.";
const LINK_CARRIES_MORE: &str = "A Svartal shell link carries nothing but the environment id: no credentials, port, path or fragment, and no other parameters.";
const LINK_ID_RULE: &str = "The environment id in a Svartal shell link is 1 to 128 characters of ASCII letters, digits, dots, underscores and hyphens, and starts with a letter or a digit.";

/// The environment id the contract allows: plain ASCII, no punctuation a
/// shell or a URL would read. It is the only string from a link that reaches
/// a command line, and it cannot mean anything but an id there.
pub fn is_environment_id(value: &str) -> bool {
    let mut characters = value.chars();
    if !characters
        .next()
        .is_some_and(|first| first.is_ascii_alphanumeric())
    {
        return false;
    }
    let rest_is_allowed =
        characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    rest_is_allowed && value.len() <= MAXIMUM_ID_CHARACTERS
}

/// A parsed shell link. One field, because the contract has one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellLink {
    pub environment_id: String,
}

/// Parse and validate one `sv://shell?environmentId=<id>` link, strictly.
///
/// The input comes from a browser, so anything that is not the canonical
/// form is refused rather than interpreted: another scheme or host,
/// credentials, a port, a path, a fragment, control characters, surrounding
/// whitespace, missing/duplicated/unknown parameters, percent-encoded or
/// otherwise malformed ids.
pub fn parse_shell_link(input: &str) -> Result<ShellLink, DeepLinkError> {
    // Raw input first: no control characters anywhere, and no surrounding
    // whitespace — that a person pastes a link with a newline on the end is
    // a reason to say so, not something to quietly normalize.
    if input.chars().any(char::is_control) {
        return Err(DeepLinkError(NOT_A_SHELL_LINK.to_string()));
    }
    if input.trim() != input {
        return Err(DeepLinkError(NOT_A_SHELL_LINK.to_string()));
    }
    let url = Url::parse(input).map_err(|_| DeepLinkError(NOT_A_SHELL_LINK.to_string()))?;
    // The url crate lowercases the scheme (schemes are case-insensitive) but
    // keeps a non-special host's case, so `SV://shell` is the same link and
    // `sv://Shell` is not one.
    if url.scheme() != SCHEME || url.host_str() != Some(SHELL_HOST) {
        return Err(DeepLinkError(NOT_A_SHELL_LINK.to_string()));
    }
    if !url.username().is_empty() || url.password().is_some() || url.port().is_some() {
        return Err(DeepLinkError(LINK_CARRIES_MORE.to_string()));
    }
    if !url.path().is_empty() || url.fragment().is_some() {
        return Err(DeepLinkError(LINK_CARRIES_MORE.to_string()));
    }
    let Some(query) = url.query() else {
        return Err(DeepLinkError(LINK_CARRIES_MORE.to_string()));
    };
    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect();
    let [(name, value)] = pairs.as_slice() else {
        return Err(DeepLinkError(LINK_CARRIES_MORE.to_string()));
    };
    if name != ENVIRONMENT_ID_PARAMETER {
        return Err(DeepLinkError(LINK_CARRIES_MORE.to_string()));
    }
    if !is_environment_id(value) {
        return Err(DeepLinkError(LINK_ID_RULE.to_string()));
    }
    // Canonical spelling only: the id's alphabet needs no percent-encoding,
    // so `%41`, `%2e` or a smuggled `%20` is not the web app's link.
    if query != format!("{ENVIRONMENT_ID_PARAMETER}={value}") {
        return Err(DeepLinkError(LINK_ID_RULE.to_string()));
    }
    Ok(ShellLink {
        environment_id: value.clone(),
    })
}

/// POSIX single quotes: the one quoting that means the same thing to every
/// shell on a Mac. The values here are a path this program chose and an id
/// the parser vetted, so this is belt and braces — but a browser's input
/// becoming a shell's commands is exactly what this module exists to prevent.
pub fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// What goes into the one-shot `.command` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandScript<'a> {
    /// The absolute `sv` that will run the shell.
    pub sv_path: &'a str,
    /// Where the script file itself lives, so it can remove itself.
    pub script_path: &'a Path,
    /// The script's own private directory.
    pub directory: &'a Path,
    /// The vetted environment id.
    pub environment_id: &'a str,
}

/// The `.command` Terminal runs.
///
/// Terminal starts the script in its own directory, so it leaves that first:
/// the script deletes its own directory below, and a deleted working
/// directory would break the `sv` that follows. The self-removal happens
/// before the `exec` only because after it this script no longer exists;
/// the interpreter is reading from an open file, so deleting the file under
/// it is safe, and a `rmdir` that fails (somebody put something in the
/// directory) must not stop the shell from opening.
pub fn open_command_script(script: &CommandScript<'_>) -> String {
    format!(
        "#!/bin/sh\n\
         # Svartal opened this for an sv:// link; the window stays, the file\n\
         # and its directory do not.\n\
         cd \"${{HOME:-/}}\" || exit 1\n\
         rm -f -- {script}\n\
         rmdir {directory} 2>/dev/null || true\n\
         exec {sv} shell {id}\n",
        script = shell_single_quote(&script.script_path.display().to_string()),
        directory = shell_single_quote(&script.directory.display().to_string()),
        sv = shell_single_quote(script.sv_path),
        id = shell_single_quote(script.environment_id),
    )
}

/// A unique `0700` directory under the system temporary directory, named
/// with random bytes so two links arriving together cannot meet in it.
fn private_temporary_directory() -> Result<PathBuf, DeepLinkError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let suffix = crate::fsutil::random_suffix()
        .map_err(|error| DeepLinkError(format!("could not name a temporary directory: {error}")))?;
    let directory = std::env::temp_dir().join(format!("sv-open-shell-{suffix}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|error| {
            DeepLinkError(format!("could not create {}: {error}", directory.display()))
        })?;
    // The create mode is masked by umask, so state it again.
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).map_err(
        |error| DeepLinkError(format!("could not secure {}: {error}", directory.display())),
    )?;
    Ok(directory)
}

/// Write the `.command` file, `0700`, inside `directory`. Public for tests,
/// which run the script with a recording `sv` instead of the real one.
pub fn write_open_command(
    directory: &Path,
    environment_id: &str,
    sv_path: &str,
) -> Result<PathBuf, DeepLinkError> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let script_path = directory.join("open-sv-shell.command");
    let script = open_command_script(&CommandScript {
        sv_path,
        script_path: &script_path,
        directory,
        environment_id,
    });
    let write = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(&script_path)
        .and_then(|mut file| file.write_all(script.as_bytes()))
        .and_then(|()| {
            std::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700))
        });
    write.map_err(|error| {
        DeepLinkError(format!(
            "could not write {}: {error}",
            script_path.display()
        ))
    })?;
    Ok(script_path)
}

/// The link, honored: write the one-shot `.command`, ask Terminal for a
/// window, and let the script delete the file on its way in.
///
/// `open` starts Terminal and answers without waiting for the script, so a
/// failure here means macOS would not take the request, and the temporary
/// directory is cleaned up by hand. From there the window is the script's.
pub fn open_link_in_terminal(
    runner: &dyn ProcessRunner,
    link: &ShellLink,
    sv_path: &str,
) -> Result<(), DeepLinkError> {
    let directory = private_temporary_directory()?;
    let script = match write_open_command(&directory, &link.environment_id, sv_path) {
        Ok(script) => script,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&directory);
            return Err(error);
        }
    };
    let opened = runner
        .run(
            OPEN_PROGRAM,
            &["-a", TERMINAL_APP, &script.display().to_string()],
        )
        .and_then(|output| {
            if output.success {
                Ok(())
            } else {
                Err(output.stderr)
            }
        });
    match opened {
        Ok(()) => Ok(()),
        Err(detail) => {
            let _ = std::fs::remove_dir_all(&directory);
            Err(DeepLinkError(format!(
                "macOS would not open a Terminal window{}",
                if detail.is_empty() {
                    String::from(".")
                } else {
                    format!(": {detail}")
                }
            )))
        }
    }
}

/// The `sv` that should take over the Terminal this link opened: the
/// executable answering the link right now, by absolute path.
pub fn current_sv_path() -> Result<String, DeepLinkError> {
    std::env::current_exe()
        .map(|path| path.display().to_string())
        .map_err(|error| DeepLinkError(format!("could not find this sv's own path: {error}")))
}

/// `sv open-url <url>` — the handler app's entry point.
///
/// It answers before any credential or network is touched: the link carries
/// no authority, so honoring it needs none.
pub fn open_url_command(out: &mut dyn Write, url: &str) -> Result<(), DeepLinkError> {
    let link = parse_shell_link(url)?;
    if !cfg!(target_os = "macos") {
        return Err(DeepLinkError(format!(
            "Opening an sv:// link in Terminal is a macOS feature. Run `sv shell {}` for the same shell.",
            link.environment_id
        )));
    }
    let sv_path = current_sv_path()?;
    open_link_in_terminal(&crate::proc::SystemRunner, &link, &sv_path)?;
    writeln!(
        out,
        "Opening a Terminal on {}. This window is done; the shell is in the new one.",
        link.environment_id
    )
    .ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(length: usize) -> String {
        let mut id = String::from("e");
        for _ in 1..length {
            id.push('a');
        }
        id
    }

    #[test]
    fn accepts_the_canonical_link() {
        assert_eq!(
            parse_shell_link("sv://shell?environmentId=env-123.4_x"),
            Ok(ShellLink {
                environment_id: "env-123.4_x".to_string()
            })
        );
        assert_eq!(
            parse_shell_link("sv://shell?environmentId=7"),
            Ok(ShellLink {
                environment_id: "7".to_string()
            })
        );
        assert_eq!(
            parse_shell_link(&format!("sv://shell?environmentId={}", id(128))),
            Ok(ShellLink {
                environment_id: id(128)
            })
        );
        assert!(parse_shell_link(&format!("sv://shell?environmentId={}", id(129))).is_err());
        // The scheme itself is case-insensitive, like every URL scheme.
        assert!(parse_shell_link("SV://shell?environmentId=env1").is_ok());
    }

    #[test]
    fn rejects_other_schemes_and_hosts() {
        for url in [
            "svartal://shell?environmentId=env1",
            "http://shell?environmentId=env1",
            "sv://machines?environmentId=env1",
            "sv://shell.example?environmentId=env1",
            // A non-special host keeps its case, so this is another host.
            "sv://Shell?environmentId=env1",
            // No authority at all: an opaque path, not a host.
            "sv:shell?environmentId=env1",
            "sv://?environmentId=env1",
        ] {
            assert!(parse_shell_link(url).is_err(), "{url} should not parse");
        }
    }

    #[test]
    fn rejects_everything_the_contract_does_not_carry() {
        for url in [
            "sv://user@shell?environmentId=env1",
            "sv://user:pass@shell?environmentId=env1",
            "sv://shell:8080?environmentId=env1",
            "sv://shell:0?environmentId=env1",
            "sv://shell/?environmentId=env1",
            "sv://shell/open?environmentId=env1",
            "sv://shell?environmentId=env1#fragment",
            "sv://shell#environmentId=env1",
            "sv://shell",
            "sv://shell?",
        ] {
            assert!(parse_shell_link(url).is_err(), "{url} should not parse");
        }
    }

    #[test]
    fn rejects_control_characters_and_surrounding_whitespace() {
        for url in [
            "sv://shell?environmentId=en\nv1",
            "sv://shell?environmentId=env1\0",
            "sv://shell?environmentId=env\u{7}1",
            "sv://shell?environmentId=env 1",
            " sv://shell?environmentId=env1",
            "sv://shell?environmentId=env1 ",
            "  sv://shell?environmentId=env1\n",
            "\tsv://shell?environmentId=env1",
        ] {
            assert!(parse_shell_link(url).is_err(), "{url:?} should not parse");
        }
    }

    #[test]
    fn rejects_duplicate_unknown_and_missing_parameters() {
        for url in [
            "sv://shell?environmentId=env1&environmentId=env2",
            "sv://shell?environmentId=env1&command=ls",
            "sv://shell?origin=https://x&environmentId=env1",
            "sv://shell?token=abc",
            "sv://shell?environmentid=env1",
            "sv://shell?environmentId=env1&",
            "sv://shell?&environmentId=env1",
        ] {
            assert!(parse_shell_link(url).is_err(), "{url} should not parse");
        }
    }

    #[test]
    fn rejects_malformed_and_encoded_ids() {
        for value in [
            "", "-env", ".env", "_env", "env id", "env/id", "env?id", "env'id", "%41", "env%2e1",
            "env%20", "envé",
        ] {
            let url = format!("sv://shell?environmentId={value}");
            assert!(
                parse_shell_link(&url).is_err(),
                "environmentId={value} should not parse"
            );
        }
    }

    #[test]
    fn single_quotes_hold_any_path() {
        assert_eq!(
            shell_single_quote("/usr/local/bin/sv"),
            "'/usr/local/bin/sv'"
        );
        assert_eq!(
            shell_single_quote("Marc's Tools/sv"),
            "'Marc'\\''s Tools/sv'"
        );
        assert_eq!(shell_single_quote(""), "''");
    }

    #[test]
    fn the_script_leaves_home_removes_itself_and_execs_a_quoted_shell() {
        let script = open_command_script(&CommandScript {
            sv_path: "/opt/homebrew/bin/sv",
            script_path: Path::new("/tmp/sv-open-shell-abc/open-sv-shell.command"),
            directory: Path::new("/tmp/sv-open-shell-abc"),
            environment_id: "env-1",
        });
        let lines: Vec<&str> = script.lines().collect();
        assert_eq!(lines[0], "#!/bin/sh");
        assert!(lines.contains(&"cd \"${HOME:-/}\" || exit 1"));
        assert!(lines.contains(&"rm -f -- '/tmp/sv-open-shell-abc/open-sv-shell.command'"));
        assert!(lines.contains(&"rmdir '/tmp/sv-open-shell-abc' 2>/dev/null || true"));
        assert_eq!(
            *lines.last().expect("the exec line"),
            "exec '/opt/homebrew/bin/sv' shell 'env-1'"
        );
        // Every line is a comment or fixed words with single-quoted literals.
        for line in lines {
            let body = line.trim();
            if body.starts_with('#') {
                continue;
            }
            assert!(
                ["cd ", "rm ", "rmdir ", "exec "]
                    .iter()
                    .any(|prefix| body.starts_with(prefix)),
                "unexpected line in the script: {body}"
            );
        }
    }
}
