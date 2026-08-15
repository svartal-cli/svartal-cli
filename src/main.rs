//! `svartal` — argument parsing, and the one place an error becomes an exit
//! code.
//!
//! Every failure this CLI produces already carries a sentence written for the
//! person running it, so the top level prints that sentence and nothing else.
//! That is the difference between "run `svartal login`" and a page of frames.

use std::io::Write as _;
use std::process::ExitCode;

use svartal::browser::{BrowserOpener, NoBrowser, SystemBrowser};
use svartal::commands::{self, Context};
use svartal::config::{environment_from_process, resolve_config};
use svartal::http::UreqTransport;
use svartal::store::FileTokenStorage;

const USAGE: &str = "Work with your Svartal machines from the terminal.

Usage: svartal <command> [options]

Commands:
  login              Sign in to Svartal in this terminal.
  logout             Revoke this terminal's Svartal credential and delete it.
  whoami             Show who this terminal is signed in as.
  machines           List the machines and workspaces you can reach.
  sessions [machine] List agent sessions on a machine.

Options:
  --json             Emit JSON instead of a table (whoami, machines, sessions).
  --no-browser       Print the sign-in URL instead of opening a browser (login).
  -h, --help         Show this message.
  -V, --version      Show the version.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let mut stderr = std::io::stderr();
            writeln!(stderr, "svartal: {message}").ok();
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
        "" => {
            // The npm CLI prints its help and exits 1 when it is given no
            // command; a shell script that runs `svartal` with an empty
            // argument should not read as success in either of them.
            write!(stdout, "{USAGE}").ok();
            return Err("no command given.".to_string());
        }
        "-V" | "--version" => {
            writeln!(stdout, "svartal v{}", env!("CARGO_PKG_VERSION")).ok();
            return Ok(());
        }
        "shell" => {
            // Honest rather than silent: the shell is phase 2 of this port.
            return Err(
                "`shell` is not in this build yet. It is the next thing being ported; the npm `@svartal/cli` has it today."
                    .to_string(),
            );
        }
        _ => {}
    }

    // Each command takes the flags it takes. A `--json` on `login` is a
    // misunderstanding worth saying out loud, not something to ignore.
    let accepted: &[&str] = match command {
        "login" => &["--no-browser"],
        "whoami" | "machines" | "sessions" => &["--json"],
        _ => &[],
    };
    let rest = &arguments[1..];
    if let Some(unknown) =
        rest.iter().find(|argument| argument.starts_with('-') && !accepted.contains(&argument.as_str()))
    {
        return Err(format!("{unknown} is not an option `svartal {command}` takes."));
    }
    let json = rest.iter().any(|argument| argument == "--json");
    let no_browser = rest.iter().any(|argument| argument == "--no-browser");
    let positional: Vec<&str> =
        rest.iter().filter(|argument| !argument.starts_with('-')).map(String::as_str).collect();

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
        "login" => commands::login(&context, &mut stdout),
        "logout" => commands::logout(&context, &mut stdout),
        "whoami" => commands::whoami(&context, &mut stdout, json),
        "machines" => commands::machines(&context, &mut stdout, json),
        "sessions" => commands::sessions(&context, &mut stdout, json, positional.first().copied()),
        other => {
            return Err(format!(
                "`{other}` is not a svartal command. Run `svartal --help` to see what is."
            ));
        }
    };
    outcome.map_err(|error| error.to_string())
}
