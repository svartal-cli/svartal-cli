//! `sv` — argument parsing, and the one place an error becomes an exit code.
//!
//! Every failure this CLI produces already carries a sentence written for the
//! person running it, so the top level prints that sentence and nothing else.
//! That is the difference between "run `sv login`" and a page of frames.

use std::io::Write as _;
use std::process::ExitCode;

use svartal::browser::{BrowserOpener, NoBrowser, SystemBrowser};
use svartal::commands::{self, Context};
use svartal::config::{environment_from_process, resolve_config};
use svartal::http::UreqTransport;
use svartal::store::FileTokenStorage;

const USAGE: &str = "Work with your Svartal machines from the terminal.

Usage: sv [command] [options]

With no command on a terminal, sv shows your environments and opens a shell on
the one you pick.

Commands:
  login              Sign in to Svartal in this terminal.
  logout             Revoke this terminal's Svartal credential and delete it.
  whoami             Show who this terminal is signed in as.
  machines           List the machines and workspaces you can reach.
  envs               List your environments, with their short names.
  name [name] [env]  Name an environment, or list the names you have given.
  sessions [machine] List agent sessions on a machine.
  shell <target>     Open a shell in a workspace you can reach.
  claude [target]    Open an interactive Claude terminal in a workspace.

A target is a short name, a workspace id, a workspace name, or a machine name.

Options:
  --json             Emit JSON instead of a table (whoami, machines, envs,
                     sessions).
  --no-browser       Print the sign-in URL instead of opening a browser (login).
  --remove <name>    Forget a short name (name).
  --terminal-id <id> Open a second, separate terminal on the same workspace
                     (shell, claude).
  -h, --help         Show this message.
  -V, --version      Show the version.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let mut stderr = std::io::stderr();
            writeln!(stderr, "sv: {message}").ok();
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<(), String> {
    let mut stdout = std::io::stdout();
    let command = arguments.first().map(String::as_str).unwrap_or_default();
    match command {
        "-h" | "--help" | "help" => {
            write!(stdout, "{USAGE}").ok();
            return Ok(());
        }
        "" if !svartal::terminal::is_interactive() => {
            // Off a terminal there is nobody to pick from a list, so this stays
            // what it was: the npm CLI prints its help and exits 1 when it is
            // given no command, and a shell script that runs `sv` with an empty
            // argument should not read as success in either of them.
            write!(stdout, "{USAGE}").ok();
            return Err("no command given.".to_string());
        }
        "-V" | "--version" => {
            writeln!(stdout, "sv v{}", env!("CARGO_PKG_VERSION")).ok();
            return Ok(());
        }
        _ => {}
    }

    // Each command takes the flags it takes. A `--json` on `login` is a
    // misunderstanding worth saying out loud, not something to ignore.
    let accepted: &[&str] = match command {
        "login" => &["--no-browser"],
        "shell" | "claude" => &["--terminal-id"],
        "name" => &["--remove"],
        "whoami" | "machines" | "envs" | "sessions" => &["--json"],
        _ => &[],
    };
    let mut json = false;
    let mut no_browser = false;
    let mut terminal_id: Option<String> = None;
    let mut removed_name: Option<String> = None;
    let mut positional: Vec<&str> = Vec::new();
    // `sv` with nothing after it has no argument list to walk, not even an
    // empty one: the command itself is the missing element.
    let mut rest = arguments.get(1..).unwrap_or_default().iter();
    while let Some(argument) = rest.next() {
        if !argument.starts_with('-') {
            positional.push(argument);
            continue;
        }
        if !accepted.contains(&argument.as_str()) {
            return Err(format!("{argument} is not an option `sv {command}` takes."));
        }
        match argument.as_str() {
            "--json" => json = true,
            "--no-browser" => no_browser = true,
            "--terminal-id" => {
                terminal_id = Some(
                    rest.next()
                        .ok_or_else(|| "--terminal-id needs a value.".to_string())?
                        .clone(),
                );
            }
            "--remove" => {
                removed_name = Some(
                    rest.next()
                        .ok_or_else(|| "--remove needs a name.".to_string())?
                        .clone(),
                );
            }
            _ => {}
        }
    }

    let environment = environment_from_process();
    let config = resolve_config(&environment).map_err(|error| error.to_string())?;
    let http = UreqTransport::new();
    let storage = FileTokenStorage::new(&config.state_directory);
    let system_browser = SystemBrowser;
    let quiet_browser = NoBrowser;
    let browser: &dyn BrowserOpener =
        if no_browser { &quiet_browser } else { &system_browser };
    let now = svartal::now_epoch_ms;
    let context = Context { config, http: &http, storage: &storage, browser, now: &now };

    let outcome = match command {
        // Nothing was typed and this is a terminal: show the environments and
        // connect a shell to the one that is picked.
        "" => commands::pick_and_open_shell(&context, &mut stdout),
        "login" => commands::login(&context, &mut stdout),
        "logout" => commands::logout(&context, &mut stdout),
        "whoami" => commands::whoami(&context, &mut stdout, json),
        "machines" => commands::machines(&context, &mut stdout, json),
        "envs" => commands::envs(&context, &mut stdout, json),
        "name" => match (removed_name.as_deref(), positional.first().copied(), positional.get(1).copied()) {
            (Some(name), _, _) => commands::remove_name(&context, &mut stdout, name),
            (None, None, _) => commands::list_names(&context, &mut stdout),
            (None, Some(name), Some(target)) => commands::name(&context, &mut stdout, name, target),
            (None, Some(name), None) => {
                return Err(format!(
                    "`sv name {name}` needs the workspace to name. Run `sv envs` to see them, then `sv name {name} <workspace>`."
                ));
            }
        },
        "sessions" => commands::sessions(&context, &mut stdout, json, positional.first().copied()),
        "shell" => {
            let Some(target) = positional.first().copied() else {
                return Err(
                    "`sv shell` needs a machine or workspace to connect to. Run `sv envs` to see them.".to_string(),
                );
            };
            commands::shell(&context, &mut stdout, Some(target), terminal_id.as_deref())
        }
        // The target is optional here: a person with one workspace has already
        // said which one by having only one.
        "claude" => commands::claude(
            &context,
            &mut stdout,
            positional.first().copied(),
            terminal_id.as_deref(),
        ),
        other => {
            return Err(format!("`{other}` is not an sv command. Run `sv --help` to see what is."));
        }
    };
    outcome.map_err(|error| error.to_string())
}
