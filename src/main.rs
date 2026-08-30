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
use svartal::shell::TerminalKind;
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
  add [pairing-url]  With a pairing URL, link that machine to your Svartal
                     account. Without one, show how to connect a new machine,
                     and hand it a token.
  name [name] [env]  Name an environment, or list the names you have given.
  sessions [machine] List agent sessions on a machine.
  shell <target>     Open a shell in a workspace you can reach.
  claude [target]    Open an interactive Claude terminal in a workspace.
  close shell <target>
                     End the shell on a workspace, without attaching to it.
  close claude [target]
                     End the Claude terminal on a workspace.
  ssh-setup <target> Set this machine's ssh config up to reach a workspace,
                     so `ssh svartal-<name>` works.
  ssh-proxy <target> Carry one ssh connection to a workspace. Run by ssh from
                     the ProxyCommand line ssh-setup wrote, not by hand.
  host up            Make this computer a Svartal machine: register it, start
                     the machine container, and wait for your workspace.
  host status        Show the machine container and your workspace on it.
  host down          Stop hosting; --purge also deletes the machine's state.

A target is a short name, a workspace id, a workspace name, or a machine name.

Options:
  --json             Emit JSON instead of a table (whoami, machines, envs,
                     sessions, add).
  --no-browser       Print the sign-in URL instead of opening a browser (login).
  --remove <name>    Forget a short name (name).
  --terminal-id <id> Open — or close — a second, separate terminal on the same
                     workspace (shell, claude, close).
  --origin <url>     The loopback origin the new box's environment server
                     listens on (add). Default http://127.0.0.1:3773.
  --publish-only     Write the runbook for a box with no managed tunnel (add).
  --name <name>      What to call this machine (host up). Defaults to this
                     computer's hostname; passing it again renames the machine.
  --image <ref>      The machine image to run (host up). Default
                     ghcr.io/svartal-cli/svartal-host:latest.
  --purge            Also delete the machine's identity and state (host down).
  --print-token      Write only a Svartal access token to stdout, to pipe into
                     the new box (add). Refused when stdout is a terminal.
  --token-file <p>   Write that token to a 0600 file instead (add).
  --print            Print the ~/.ssh/config block instead of writing it
                     (ssh-setup).
  --reset-hosts      Forget the workspace host key recorded for this host
                     first (ssh-setup).
  -h, --help         Show this message.
  -V, --version      Show the version.
";

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    match run(&arguments) {
        Ok(0) => ExitCode::SUCCESS,
        // `sv ssh-proxy` ends with the connection's own status, because that is
        // the only thing `ssh` can still read once the pump has started
        // (`ssh-bridge.md` §8.5). Every other command answers 0 or fails.
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            let mut stderr = std::io::stderr();
            writeln!(stderr, "sv: {message}").ok();
            ExitCode::FAILURE
        }
    }
}

fn run(arguments: &[String]) -> Result<u8, String> {
    let mut stdout = std::io::stdout();
    let command = arguments.first().map(String::as_str).unwrap_or_default();
    match command {
        "-h" | "--help" | "help" => {
            write!(stdout, "{USAGE}").ok();
            return Ok(0);
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
            return Ok(0);
        }
        _ => {}
    }

    // Each command takes the flags it takes. A `--json` on `login` is a
    // misunderstanding worth saying out loud, not something to ignore.
    let accepted: &[&str] = match command {
        "login" => &["--no-browser"],
        "shell" | "claude" | "close" => &["--terminal-id"],
        "name" => &["--remove"],
        "ssh-setup" => &["--print", "--reset-hosts"],
        "add" => &["--json", "--origin", "--publish-only", "--print-token", "--token-file"],
        "host" => &["--image", "--name", "--purge"],
        "whoami" | "machines" | "envs" | "sessions" => &["--json"],
        _ => &[],
    };
    let mut json = false;
    let mut no_browser = false;
    let mut terminal_id: Option<String> = None;
    let mut removed_name: Option<String> = None;
    let mut origin: Option<String> = None;
    let mut publish_only = false;
    let mut print_token = false;
    let mut token_file: Option<String> = None;
    let mut print_block = false;
    let mut reset_hosts = false;
    let mut host_image: Option<String> = None;
    let mut host_name: Option<String> = None;
    let mut purge = false;
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
            "--origin" => {
                origin = Some(
                    rest.next()
                        .ok_or_else(|| "--origin needs a URL.".to_string())?
                        .clone(),
                );
            }
            "--publish-only" => publish_only = true,
            "--print" => print_block = true,
            "--reset-hosts" => reset_hosts = true,
            "--print-token" => print_token = true,
            "--purge" => purge = true,
            "--name" => {
                host_name = Some(
                    rest.next()
                        .ok_or_else(|| "--name needs a name for this machine.".to_string())?
                        .clone(),
                );
            }
            "--image" => {
                host_image = Some(
                    rest.next()
                        .ok_or_else(|| "--image needs an image reference.".to_string())?
                        .clone(),
                );
            }
            "--token-file" => {
                token_file = Some(
                    rest.next()
                        .ok_or_else(|| "--token-file needs a path.".to_string())?
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
        // One verb, two modes, told apart by the argument. A pairing URL names
        // the one machine to link, so the flow runs against it; no URL means
        // the runbook, written for a machine that has no URL to give yet.
        "add" => match svartal::add::route(
            positional.first().copied(),
            json || origin.is_some() || publish_only || print_token || token_file.is_some(),
        )? {
            svartal::add::AddRoute::Link(pairing_url) => {
                commands::add_link(&context, &mut stdout, pairing_url)
            }
            svartal::add::AddRoute::Runbook => {
                // The two token modes are one decision, so asking for both is a
                // question this program cannot answer rather than a preference to
                // resolve.
                let mode = match (print_token, token_file.clone()) {
                    (true, Some(_)) => return Err(svartal::add::BOTH_TOKEN_MODES.to_string()),
                    (true, None) => commands::AddMode::PrintToken,
                    (false, Some(path)) => commands::AddMode::TokenFile(path),
                    (false, None) if json => commands::AddMode::Json,
                    (false, None) => commands::AddMode::Runbook,
                };
                commands::add(
                    &context,
                    &mut stdout,
                    mode,
                    origin.as_deref(),
                    publish_only,
                    svartal::terminal::stdout_is_terminal(),
                )
            }
        },
        // `ssh` runs this one, and reads its exit status as the connection's.
        // It is answered before the ordinary dispatch so that status can leave
        // this function instead of being flattened to success or failure.
        "ssh-proxy" => {
            let Some(target) = positional.first().copied() else {
                return Err(
                    "`sv ssh-proxy` needs the workspace to connect to. It is normally run by ssh, from the ProxyCommand line `sv ssh-setup` wrote."
                        .to_string(),
                );
            };
            let code = commands::ssh_proxy(&context, target).map_err(|error| error.to_string())?;
            return Ok(u8::try_from(code).unwrap_or(1));
        }
        "ssh-setup" => {
            let Some(target) = positional.first().copied() else {
                return Err(
                    "`sv ssh-setup` needs the machine or workspace to set up. Run `sv envs` to see them."
                        .to_string(),
                );
            };
            commands::ssh_setup(&context, &mut stdout, &environment, target, print_block, reset_hosts)
        }
        "sessions" => commands::sessions(&context, &mut stdout, json, positional.first().copied()),
        // This computer as a machine: one verb, three moments.
        "host" => {
            let docker = svartal::host::ProcessDocker;
            match positional.first().copied() {
                Some("up") => commands::host_up(
                    &context,
                    &mut stdout,
                    &docker,
                    host_name.as_deref(),
                    host_image.as_deref(),
                ),
                Some("status") => commands::host_status(&context, &mut stdout, &docker),
                Some("down") => commands::host_down(&context, &mut stdout, &docker, purge),
                _ => {
                    return Err(
                        "`sv host` needs one of: up (make this computer a Svartal machine), status, down.".to_string(),
                    );
                }
            }
        }
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
        "close" => {
            // The kind is a positional word mirroring the open verbs, so what
            // `sv shell` opened, `sv close shell` closes.
            let kind = match positional.first().copied() {
                Some("shell") => TerminalKind::Shell,
                Some("claude") => TerminalKind::Claude,
                Some(other) => {
                    return Err(format!(
                        "`sv close {other}` is not a thing sv can close. It is `sv close shell <target>` or `sv close claude [target]`."
                    ));
                }
                None => {
                    return Err(
                        "`sv close` needs to know which kind of terminal to close: `sv close shell <target>` or `sv close claude [target]`."
                            .to_string(),
                    );
                }
            };
            let target = positional.get(1).copied();
            if kind == TerminalKind::Shell && target.is_none() {
                // The same rule as `sv shell`: a shell target is never guessed.
                return Err(
                    "`sv close shell` needs the machine or workspace whose shell to close. Run `sv envs` to see them."
                        .to_string(),
                );
            }
            commands::close(&context, &mut stdout, kind, target, terminal_id.as_deref())
        }
        other => {
            return Err(format!("`{other}` is not an sv command. Run `sv --help` to see what is."));
        }
    };
    outcome.map(|()| 0).map_err(|error| error.to_string())
}
