//! The commands themselves.
//!
//! Port of `src/commands.ts`. Each function takes the writer it prints to, so
//! a test can assert on the exact lines the way the TypeScript tests assert on
//! a recording console.
//!
//! One difference from the reference: `machines` fetches the two listings one
//! after the other rather than concurrently. Two sequential GETs in a
//! short-lived process are not worth an async runtime.

use std::io::Write;

use crate::api::{self, LinkRecord, Machine};
use crate::browser::BrowserOpener;
use crate::config::Config;
use crate::http::HttpTransport;
use crate::loopback::{CALLBACK_TIMEOUT, LoopbackError, LoopbackServer};
use crate::oidc::{OidcClient, OidcConfig, Session};
use crate::shell::TerminalKind;
use crate::shortnames::{self, Shortnames};
use crate::sshproxy;
use crate::store::TokenStorage;
use crate::target::ShellTarget;
use crate::view;

#[derive(Debug)]
pub struct CliError(pub String);

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CliError {}

impl CliError {
    fn of(error: impl std::fmt::Display) -> Self {
        Self(error.to_string())
    }
}

/// The message a command that reads data gives when nobody is signed in. It
/// never opens a browser on its own: a listing should not take over the
/// terminal.
pub const NOT_SIGNED_IN: &str = "You are not signed in to Svartal. Run `sv login`.";

pub struct Context<'a> {
    pub config: Config,
    pub http: &'a dyn HttpTransport,
    pub storage: &'a dyn TokenStorage,
    pub browser: &'a dyn BrowserOpener,
    pub now: &'a dyn Fn() -> i64,
}

impl<'a> Context<'a> {
    fn client(&self, redirect_index: usize) -> Result<OidcClient<'_>, CliError> {
        let redirect = self
            .config
            .redirects
            .get(redirect_index)
            .ok_or_else(|| CliError(NOT_SIGNED_IN.to_string()))?;
        OidcClient::new(
            OidcConfig::from_cli(&self.config, redirect),
            self.http,
            self.storage,
            self.now,
        )
        .map_err(CliError::of)
    }

    /// The stored session, refreshed if it is close to expiry. Fails rather
    /// than silently opening a browser.
    fn current_session(&self) -> Result<Session, CliError> {
        match self.client(0)?.existing_session().map_err(CliError::of)? {
            Some(session) => Ok(session),
            None => Err(CliError(NOT_SIGNED_IN.to_string())),
        }
    }
}

fn display_name(session: &Session) -> String {
    session.user.preferred_username.clone().unwrap_or_else(|| session.user.sub.clone())
}

pub fn login(context: &Context<'_>, out: &mut dyn Write) -> Result<(), CliError> {
    // A stored credential that cannot be verified is exactly the case
    // `sv login` exists to repair, so a failure here must not stop the
    // command.
    let existing = context.client(0)?.existing_session().unwrap_or(None);
    if let Some(session) = existing {
        writeln!(out, "Already signed in as {}.", display_name(&session)).ok();
        configure_knit(context, out, &session);
        return Ok(());
    }
    let session = sign_in(context, out)?;
    writeln!(out, "Signed in as {}.", display_name(&session)).ok();
    configure_knit(context, out, &session);
    Ok(())
}

/// Signing in signs knit in too, the way `gh auth login` leaves git working:
/// one knit API token is minted from this session and written into knit's
/// user-global config. A remote that already has a token is left exactly as
/// it is — it may carry hand-picked scopes a fresh default-scope token would
/// silently lose — and nothing here can fail the login itself.
fn configure_knit(context: &Context<'_>, out: &mut dyn Write, session: &Session) {
    let api_url = context.config.api_base_url.trim_end_matches('/').to_string();

    // The token is minted against sv's API origin, but the remote knit gets
    // is the web origin people already use in knit configs: `api.svartal.com`
    // and `svartal.com` serve the same API, and only the latter matches a
    // remote somebody added by hand before sv could do it for them.
    let api_host = api_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    let host = api_host.strip_prefix("api.").unwrap_or(&api_host).to_string();
    let scheme = if api_url.starts_with("http://") { "http" } else { "https" };
    let url = format!("{scheme}://{host}");
    let remote_name = host
        .split(['.', ':'])
        .next()
        .filter(|label| !label.is_empty())
        .unwrap_or("svartal")
        .to_string();

    let path = match crate::knit_config::global_config_path() {
        Ok(path) => path,
        Err(reason) => {
            writeln!(out, "knit was not configured: {reason}").ok();
            return;
        }
    };
    match crate::knit_config::remote_state(&path, &remote_name, &url) {
        crate::knit_config::RemoteState::Configured => return,
        crate::knit_config::RemoteState::OtherServer { url: other } => {
            writeln!(
                out,
                "knit was not configured: it already has a remote `{remote_name}` pointing at {other}."
            )
            .ok();
            return;
        }
        crate::knit_config::RemoteState::Missing => {}
    }

    let minted = match api::mint_knit_token(
        context.http,
        &api_url,
        &session.access_token,
        &format!("sv login {host}"),
    ) {
        Ok(minted) => minted,
        Err(error) => {
            writeln!(out, "knit was not configured: {error}").ok();
            return;
        }
    };
    match crate::knit_config::install_remote(&path, &remote_name, &url, &minted.secret) {
        Ok(_installed) => {
            writeln!(out, "knit is connected to {host}: remote `{remote_name}` in {}.", path.display())
                .ok();
            if let Some(expires_at) = &minted.expires_at {
                writeln!(out, "Its token expires {expires_at}; `sv login` renews it.").ok();
            }
        }
        Err(reason) => {
            writeln!(out, "knit was not configured: {reason}").ok();
        }
    }
}

/// The whole headless sign-in: listen on a registered loopback callback, send
/// the person to the authorization endpoint, and exchange the code that comes
/// back. Falls through to the next registered port when one is already held,
/// so a second terminal can still sign in.
fn sign_in(context: &Context<'_>, out: &mut dyn Write) -> Result<Session, CliError> {
    let ports: Vec<u16> = context.config.redirects.iter().map(|entry| entry.port).collect();
    for (index, redirect) in context.config.redirects.iter().enumerate() {
        let server = match LoopbackServer::bind(redirect) {
            Ok(server) => server,
            Err(LoopbackError::PortInUse { .. }) => continue,
            Err(error) => return Err(CliError::of(error)),
        };
        let mut client = context.client(index)?;
        let authorization = client.begin_authorization().map_err(CliError::of)?;
        let opened = context.browser.open(&authorization.url);
        writeln!(
            out,
            "{}",
            if opened {
                "Opening your browser to finish signing in. If nothing happens, open this URL:"
            } else {
                "Open this URL to finish signing in:"
            }
        )
        .ok();
        writeln!(out, "{}", authorization.url).ok();
        writeln!(out).ok();
        let callback_url = server.wait_for_callback(CALLBACK_TIMEOUT).map_err(CliError::of)?;
        return client
            .complete_authorization(authorization.transaction, &callback_url)
            .map_err(CliError::of);
    }
    Err(CliError(format!(
        "Every sign-in callback port is in use ({}). Close whatever is holding them and run `sv login` again.",
        ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ")
    )))
}

pub fn logout(context: &Context<'_>, out: &mut dyn Write) -> Result<(), CliError> {
    let removed = context.client(0)?.sign_out().map_err(CliError::of)?;
    writeln!(
        out,
        "{}",
        if removed {
            "Signed out. The refresh token was revoked."
        } else {
            "There was nothing to sign out of."
        }
    )
    .ok();
    Ok(())
}

pub fn whoami(context: &Context<'_>, out: &mut dyn Write, json: bool) -> Result<(), CliError> {
    let session = context.current_session()?;
    if json {
        writeln!(out, "{}", view::format_user_json(&session.user)).ok();
        return Ok(());
    }
    for line in view::describe_user(&session.user) {
        writeln!(out, "{line}").ok();
    }
    Ok(())
}

fn load_view(context: &Context<'_>) -> Result<view::MachinesView, CliError> {
    Ok(load_session_and_view(context)?.1)
}

/// The session and the joined listing, fetched once.
///
/// `shell` needs both, and asking the provider twice for the same session (or
/// the API twice for the same listing) inside one command would be two round
/// trips paid for nothing. The two listings go to different services — the
/// Svartal API and the relay — and neither depends on the other's answer, so
/// they are fetched concurrently and the command waits only for the slower
/// one. When both fail, the API's error is the one reported, which is the
/// sentence the sequential fetch produced.
fn load_session_and_view(
    context: &Context<'_>,
) -> Result<(Session, view::MachinesView), CliError> {
    let session = context.current_session()?;
    // Only the transport crosses into the second thread; the rest of the
    // context (storage, browser, clock) stays on this one.
    let http = context.http;
    let relay_url = &context.config.relay_url;
    let access_token = &session.access_token;
    let (machines, links) = std::thread::scope(|scope| {
        let links =
            scope.spawn(move || api::list_linked_environments(http, relay_url, access_token));
        let machines =
            api::list_machines(context.http, &context.config.api_base_url, &session.access_token);
        (machines, links.join().expect("the relay listing thread never panics"))
    });
    let machines: Vec<Machine> = machines.map_err(CliError::of)?;
    let links: Vec<LinkRecord> = links.map_err(CliError::of)?;
    Ok((session, view::build_machines_view(&machines, &links)))
}

/// The stored short names, or none.
///
/// Read paths never fail over this file: a name that cannot be read costs the
/// person a shorthand, and refusing to open a shell because of it would cost
/// them the shell. `sv name`, which writes, reports the error instead.
fn stored_shortnames(context: &Context<'_>) -> Shortnames {
    shortnames::read_shortnames(&context.config.state_directory).unwrap_or_default()
}

pub fn machines(context: &Context<'_>, out: &mut dyn Write, json: bool) -> Result<(), CliError> {
    let loaded = load_view(context)?;
    if json {
        writeln!(out, "{}", view::format_machines_json(&loaded)).ok();
        return Ok(());
    }
    writeln!(out, "{}", view::format_machines_view(&loaded)).ok();
    if !loaded.rows.is_empty() {
        writeln!(out).ok();
        writeln!(out, "{}", view::MACHINE_STATE_NOTE).ok();
    }
    Ok(())
}

/// `sv envs`.
///
/// The same two listings `sv machines` joins, with the workspace as the subject
/// and the short name in front of it. `sv machines` is unchanged: it is the
/// command the npm CLI also has, and the two are meant to print the same thing.
pub fn envs(context: &Context<'_>, out: &mut dyn Write, json: bool) -> Result<(), CliError> {
    let view = load_view(context)?;
    let rows = view::build_env_rows(&view, &stored_shortnames(context));
    if json {
        writeln!(out, "{}", view::format_envs_json(&rows)).ok();
        return Ok(());
    }
    writeln!(out, "{}", view::format_envs_view(&rows)).ok();
    if !rows.is_empty() {
        writeln!(out).ok();
        writeln!(out, "{}", view::MACHINE_STATE_NOTE).ok();
    }
    Ok(())
}

/// `sv name` — the assignments, without asking the network for anything.
pub fn list_names(context: &Context<'_>, out: &mut dyn Write) -> Result<(), CliError> {
    let stored =
        shortnames::read_shortnames(&context.config.state_directory).map_err(CliError::of)?;
    if stored.is_empty() {
        writeln!(out, "No workspace names yet. Name one with `sv name <name> <workspace>`.").ok();
        return Ok(());
    }
    let table = view::render_table(
        &["SHORTNAME", "WORKSPACE ID"],
        &stored
            .entries()
            .map(|(name, environment_id)| vec![name.to_string(), environment_id.to_string()])
            .collect::<Vec<_>>(),
    );
    writeln!(out, "{table}").ok();
    Ok(())
}

/// `sv name <shortname> <workspace>`.
///
/// The workspace is resolved by the ordinary rules, so the thing being named
/// can itself be a machine name, a label, a workspace id, or an older short
/// name. A workspace that is not linked can still be named: naming is a note to
/// yourself, not a connection.
pub fn name(
    context: &Context<'_>,
    out: &mut dyn Write,
    shortname: &str,
    target: &str,
) -> Result<(), CliError> {
    let shortname = shortname.trim().to_lowercase();
    if !shortnames::is_valid_shortname(&shortname) {
        return Err(CliError(format!(
            "{shortname} is not a usable name. {}",
            shortnames::SHORTNAME_RULE
        )));
    }
    let view = load_view(context)?;
    let mut stored =
        shortnames::read_shortnames(&context.config.state_directory).map_err(CliError::of)?;

    // A name that is already a workspace id could never be resolved: ids win.
    // Storing it would leave a name that silently does nothing.
    if crate::target::shell_targets(&view)
        .iter()
        .any(|candidate| candidate.environment_id.to_lowercase() == shortname)
    {
        return Err(CliError(format!(
            "{shortname} is already a workspace id, so a name like that would never be used. Pick another word."
        )));
    }

    let resolved = match crate::target::resolve_shell_target(&view, &stored, target) {
        crate::target::Resolution::Resolved(target) => target,
        crate::target::Resolution::Ambiguous(candidates) => {
            return Err(CliError::of(crate::target::TargetError::Ambiguous {
                argument: target.to_string(),
                candidates: crate::target::format_target_candidates(&candidates),
            }));
        }
        crate::target::Resolution::Missing(_) => {
            return Err(CliError(format!(
                "No workspace called {target}. Run `sv envs` to see them:\n\n{}",
                view::format_envs_view(&view::build_env_rows(&view, &stored))
            )));
        }
    };

    let assignment =
        stored.assign(&shortname, &resolved.environment_id).map_err(CliError::of)?;
    shortnames::write_shortnames(&context.config.state_directory, &stored)
        .map_err(CliError::of)?;

    writeln!(out, "{shortname} is {} ({}).", resolved.label, resolved.environment_id).ok();
    if let Some(previous) = assignment.replaced_shortname {
        writeln!(out, "It used to be {previous}.").ok();
    }
    if let Some(previous) = assignment.replaced_environment {
        writeln!(out, "{shortname} used to mean {previous}.").ok();
    }
    Ok(())
}

/// `sv name --remove <shortname>`. Offline: the workspace is untouched.
pub fn remove_name(
    context: &Context<'_>,
    out: &mut dyn Write,
    shortname: &str,
) -> Result<(), CliError> {
    let shortname = shortname.trim().to_lowercase();
    let mut stored =
        shortnames::read_shortnames(&context.config.state_directory).map_err(CliError::of)?;
    match stored.remove(&shortname) {
        None => Err(CliError(format!("There is no workspace named {shortname}."))),
        Some(environment_id) => {
            shortnames::write_shortnames(&context.config.state_directory, &stored)
                .map_err(CliError::of)?;
            writeln!(out, "{shortname} is no longer a name for {environment_id}.").ok();
            Ok(())
        }
    }
}

/// `sv shell <machine-or-workspace>`.
///
/// Resolve, connect, then hand the terminal over. The remote shell is
/// deliberately left running when the CLI exits: reattaching is the normal
/// case, and the closing line says so rather than implying the shell was
/// killed.
pub fn shell(
    context: &Context<'_>,
    out: &mut dyn Write,
    target: Option<&str>,
    terminal_id: Option<&str>,
) -> Result<(), CliError> {
    let (session, view) = load_session_and_view(context)?;
    let target = crate::target::select_target(&view, &stored_shortnames(context), target)
        .map_err(CliError::of)?;
    open_detached_terminal(context, out, TerminalKind::Shell, &session, &target, terminal_id)
}

/// `sv claude [machine-or-workspace]`.
///
/// The same command as `sv shell`, in the sibling namespace: what the
/// workspace starts behind it is an interactive Claude session inside the
/// machine broker's runner container, because that is the only place a
/// brokered credential may be used. Everything a person can see here — the
/// reattach, the raw-mode pump, the closing line — is the shell's, on purpose.
pub fn claude(
    context: &Context<'_>,
    out: &mut dyn Write,
    target: Option<&str>,
    terminal_id: Option<&str>,
) -> Result<(), CliError> {
    let (session, view) = load_session_and_view(context)?;
    let target = crate::target::select_target(&view, &stored_shortnames(context), target)
        .map_err(CliError::of)?;
    open_detached_terminal(context, out, TerminalKind::Claude, &session, &target, terminal_id)
}

/// Bare `sv` on a terminal: the list, then a shell on what was picked.
///
/// Quitting the list is not a failure. Nothing was asked for and nothing went
/// wrong, so it exits 0 and says nothing — the same as pressing Ctrl-C at a
/// prompt.
pub fn pick_and_open_shell(context: &Context<'_>, out: &mut dyn Write) -> Result<(), CliError> {
    let (session, view) = load_session_and_view(context)?;
    let shortnames = stored_shortnames(context);
    let rows = crate::picker::build_picker_rows(&view, &shortnames);
    if rows.is_empty() {
        writeln!(out, "{}", view::NO_ENVIRONMENTS).ok();
        return Ok(());
    }
    let Some(chosen) = crate::picker::pick(rows) else {
        return Ok(());
    };
    // Through the ordinary rules, by workspace id: a workspace that cannot be
    // connected to gets the same sentence it would have got from
    // `sv shell <id>`, rather than a second explanation written for the picker.
    let target = crate::target::select_shell_target(&view, &shortnames, &chosen.environment_id)
        .map_err(CliError::of)?;
    open_detached_terminal(context, out, TerminalKind::Shell, &session, &target, None)
}

fn open_detached_terminal(
    context: &Context<'_>,
    out: &mut dyn Write,
    kind: TerminalKind,
    session: &Session,
    target: &ShellTarget,
    terminal_id: Option<&str>,
) -> Result<(), CliError> {
    let dpop_key =
        crate::dpop::load_or_create_key(&context.config.state_directory).map_err(CliError::of)?;
    let connection = crate::shell::connect_workspace(
        context.http,
        &crate::shell::ConnectInput {
            kind,
            relay_url: &context.config.relay_url,
            client_id: &context.config.client_id,
            access_token: &session.access_token,
            target,
            dpop_key: &dpop_key,
            client_metadata: crate::shell::cli_client_metadata(),
            scopes: &crate::workspace::SHELL_SCOPES,
        },
    )
    .map_err(CliError::of)?;

    let transport = crate::ws::WebSocketTransport::connect(&connection.socket_url).map_err(|error| {
        CliError::of(crate::shell::ShellError::Connection {
            kind,
            label: target.label.clone(),
            detail: error.to_string(),
        })
    })?;
    let mut rpc = crate::rpc::RpcClient::new(transport);

    let size = crate::terminal::terminal_size();
    let shell_session = crate::shell::open_shell(
        &mut rpc,
        &crate::shell::OpenInput {
            kind,
            label: &target.label,
            subject: &session.user.sub,
            terminal_id,
            environment_id: &target.environment_id,
            size,
            term: crate::shell::local_term(),
            colorterm: crate::shell::local_colorterm(),
        },
    )
    .map_err(CliError::of)?;

    writeln!(
        out,
        "{}",
        if shell_session.reattached {
            format!(
                "Back in your {} on {} ({}).",
                kind.noun(),
                target.label,
                shell_session.cwd
            )
        } else {
            format!("{} on {} ({}).", kind.title(), target.label, shell_session.cwd)
        }
    )
    .ok();

    // Raw mode from here, restored by the guard on every way out of this
    // function: a normal end, an error, a panic, or a signal.
    let raw = crate::terminal::RawMode::enter();
    let mut local = crate::terminal::ProcessTerminal::new(raw.interactive());
    let outcome = crate::shell::run_shell_pump(
        &mut rpc,
        &mut local,
        &crate::shell::PumpInput {
            session: &shell_session,
            label: &target.label,
            subject: &session.user.sub,
        },
    );
    drop(raw);
    rpc.transport_mut().close();

    let outcome = outcome.map_err(CliError::of)?;
    writeln!(out, "{}", crate::shell::describe_shell_outcome(kind, &outcome, &target.label)).ok();
    Ok(())
}

/// What `sv add` was asked to do. One command with three outputs, because they
/// are three steps of one job: read the runbook, then hand the token over the
/// way the runbook says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddMode {
    /// The runbook, for a person.
    Runbook,
    /// The runbook's facts, for a script. Never the token.
    Json,
    /// The access token on stdout and nothing else, so it can be piped
    /// straight into `ssh newbox 'brok link … --token-stdin'`.
    PrintToken,
    /// The access token in a `0600` file, for a person who has to copy it.
    TokenFile(String),
}

/// `sv add` — how a new machine joins, and the safe ways to give it the one
/// secret it needs.
///
/// Every mode asks for the current session first, even the ones that print no
/// token. A runbook written from an expired credential would send someone
/// through an install for a link that was going to fail, and the check costs
/// one already-cached round trip.
pub fn add(
    context: &Context<'_>,
    out: &mut dyn Write,
    mode: AddMode,
    origin: Option<&str>,
    publish_only: bool,
    stdout_is_terminal: bool,
) -> Result<(), CliError> {
    let origin = origin.map(str::trim).unwrap_or(crate::add::DEFAULT_ORIGIN).to_string();
    if !crate::add::is_loopback_origin(&origin) {
        return Err(CliError(format!(
            "{origin} is not a loopback origin, and `brok link` would refuse it. Use something like {}.",
            crate::add::DEFAULT_ORIGIN
        )));
    }
    let session = context.current_session()?;
    let plan = crate::add::MachinePlan {
        relay_url: context.config.relay_url.clone(),
        issuer: context.config.issuer.clone(),
        subject: session.user.sub.clone(),
        origin,
        publish_only,
        token_expires_in_seconds: (session.access_expires_at_epoch_ms - (context.now)()) / 1_000,
    };

    match mode {
        AddMode::Runbook => {
            writeln!(out, "{}", crate::add::runbook(&plan)).ok();
        }
        AddMode::Json => {
            writeln!(out, "{}", crate::add::runbook_json(&plan)).ok();
        }
        AddMode::PrintToken => {
            // The one place this CLI writes a secret to stdout, so it is also
            // the one place it checks where stdout goes.
            if stdout_is_terminal {
                return Err(CliError(crate::add::PRINT_TOKEN_ON_TERMINAL.to_string()));
            }
            out.write_all(&crate::add::token_file_body(&session.access_token)).ok();
        }
        AddMode::TokenFile(path) => {
            let path = std::path::PathBuf::from(&path);
            crate::fsutil::write_private_file(&path, &crate::add::token_file_body(&session.access_token))
                .map_err(CliError::of)?;
            writeln!(out, "{}", crate::add::token_file_note(&path.display().to_string(), &plan))
                .ok();
        }
    }
    Ok(())
}

/// `sv ssh-proxy <target>`: the SSH client's transport.
///
/// A person does not run this; `ssh` does, from the `ProxyCommand` line
/// `sv ssh-setup` wrote. Two things follow, and both are load-bearing:
///
/// * **It takes no writer.** stdout is the SSH transport
///   (`ssh-bridge.md` §8.1), so this command has no "connected to …" line, no
///   summary and no closing sentence — the only thing that may ever reach
///   stdout here is a `STDOUT` payload. Failures still print, on stderr,
///   through the top level.
/// * **It returns the exit status.** A `ProxyCommand`'s exit status is all
///   `ssh` has left to read once the pump has started (§8.5), so `main` puts
///   this on the process.
pub fn ssh_proxy(context: &Context<'_>, target: &str) -> Result<i32, CliError> {
    ssh_proxy_with(context, target, |socket_url| {
        crate::ws::WebSocketTransport::connect(socket_url).map_err(|error| error.to_string())
    })
}

/// `ssh_proxy`, with the WebSocket step injectable so a test can script the
/// wire.
pub fn ssh_proxy_with<T, F>(context: &Context<'_>, target: &str, connect: F) -> Result<i32, CliError>
where
    T: crate::ws::BinaryTransport,
    F: FnOnce(&str) -> Result<T, String>,
{
    let (session, view) = load_session_and_view(context)?;
    // The target is never guessed here: `ssh` has already been told which host
    // to reach, and the argument is the resolved name that host stands for.
    // That argument is also what the alias is built from, so `known_hosts` is
    // keyed by the same word `ssh` looked the host up under.
    let alias = sshproxy::host_alias(target);
    let target = crate::target::select_shell_target(&view, &stored_shortnames(context), target)
        .map_err(CliError::of)?;

    let key = sshproxy::ensure_client_key(&context.config.state_directory).map_err(CliError::of)?;
    let dpop_key =
        crate::dpop::load_or_create_key(&context.config.state_directory).map_err(CliError::of)?;
    let socket_url = sshproxy::connect_bridge(
        context.http,
        &sshproxy::BridgeConnectInput {
            relay_url: &context.config.relay_url,
            client_id: &context.config.client_id,
            access_token: &session.access_token,
            target: &target,
            dpop_key: &dpop_key,
            client_metadata: crate::shell::cli_client_metadata(),
        },
    )
    .map_err(CliError::of)?;

    let mut transport = connect(&socket_url).map_err(|detail| {
        CliError::of(sshproxy::SshError::Connect { label: target.label.clone(), detail })
    })?;
    let known_hosts = sshproxy::known_hosts_path(&context.config.state_directory);
    let mut stdio = sshproxy::ProcessStdio::new();
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &sshproxy::ProxyInput {
            label: &target.label,
            public_key: &key.public_key,
            client_name: Some(sshproxy::CLIENT_NAME),
            known_hosts: sshproxy::KnownHostsTarget { path: &known_hosts, alias: &alias },
            ping_interval: sshproxy::PING_INTERVAL,
        },
    );
    crate::ws::BinaryTransport::shutdown(&mut transport);
    Ok(outcome.map_err(CliError::of)?.exit_code)
}

/// `sv ssh-setup <target>`: make `ssh svartal-<name>` work.
///
/// Applying is the default, because the thing a person asked for is a working
/// host, not a block of text to paste. `--print` is the opt-out.
///
/// The word in the `ProxyCommand` — and in the alias built from it — is the
/// short name recorded with `sv name` when there is one, and otherwise the
/// workspace id. Both resolve on their own, which is the whole requirement:
/// `ssh` hands that word straight back to `sv ssh-proxy` with nothing else, so
/// the display name the person typed ("My Box", a label the workspace can
/// rename underneath them) would not survive the trip.
pub fn ssh_setup(
    context: &Context<'_>,
    out: &mut dyn Write,
    environment: &crate::config::Environment,
    target: &str,
    print: bool,
    reset_hosts: bool,
) -> Result<(), CliError> {
    let (_session, view) = load_session_and_view(context)?;
    let shortnames = stored_shortnames(context);
    let resolved =
        crate::target::select_shell_target(&view, &shortnames, target).map_err(CliError::of)?;
    let ssh_config_path = sshproxy::default_ssh_config_path(environment).map_err(CliError::of)?;
    // The alias is built from this same word, so `known_hosts` is keyed by the
    // host `ssh` looks up and the key recorded on `READY` is the one it checks.
    let name = shortnames
        .shortname_of(&resolved.environment_id)
        .map(str::to_string)
        .unwrap_or_else(|| resolved.environment_id.clone());

    let outcome = sshproxy::run_ssh_setup(&sshproxy::SetupInput {
        state_directory: &context.config.state_directory,
        target: &name,
        binary: &sshproxy::invoked_binary_path(),
        ssh_config_path: &ssh_config_path,
        print,
        reset_hosts,
    })
    .map_err(CliError::of)?;

    if print {
        writeln!(out, "{}", outcome.block).ok();
        return Ok(());
    }
    for line in sshproxy::describe_ssh_setup(&outcome) {
        writeln!(out, "{line}").ok();
    }
    Ok(())
}

/// `sv close shell <target>` / `sv close claude [target]`.
///
/// The teardown quitting deliberately is not: `sv shell` and `sv claude`
/// detach and leave the remote terminal running, so until this verb, ending
/// one meant attaching first. This resolves the target exactly as the open
/// verbs do, connects the same way, and tells the workspace to kill the PTY —
/// no attach, no raw mode, and a plain sentence when nothing was running.
pub fn close(
    context: &Context<'_>,
    out: &mut dyn Write,
    kind: TerminalKind,
    target: Option<&str>,
    terminal_id: Option<&str>,
) -> Result<(), CliError> {
    close_with(context, out, kind, target, terminal_id, |socket_url| {
        crate::ws::WebSocketTransport::connect(socket_url).map_err(|error| error.to_string())
    })
}

/// `close`, with the WebSocket step injectable so a test can script the wire.
pub fn close_with<T, F>(
    context: &Context<'_>,
    out: &mut dyn Write,
    kind: TerminalKind,
    target: Option<&str>,
    terminal_id: Option<&str>,
    connect: F,
) -> Result<(), CliError>
where
    T: crate::rpc::RpcTransport,
    F: FnOnce(&str) -> Result<T, String>,
{
    let (session, view) = load_session_and_view(context)?;
    let target = crate::target::select_target(&view, &stored_shortnames(context), target)
        .map_err(CliError::of)?;

    let dpop_key =
        crate::dpop::load_or_create_key(&context.config.state_directory).map_err(CliError::of)?;
    let connection = crate::shell::connect_workspace(
        context.http,
        &crate::shell::ConnectInput {
            kind,
            relay_url: &context.config.relay_url,
            client_id: &context.config.client_id,
            access_token: &session.access_token,
            target: &target,
            dpop_key: &dpop_key,
            client_metadata: crate::shell::cli_client_metadata(),
            scopes: &crate::workspace::CLOSE_SCOPES,
        },
    )
    .map_err(CliError::of)?;

    let transport = connect(&connection.socket_url).map_err(|detail| {
        CliError::of(crate::shell::ShellError::NotClosed {
            kind,
            label: target.label.clone(),
            detail,
        })
    })?;
    let mut rpc = crate::rpc::RpcClient::new(transport);

    let outcome = crate::shell::close_shell(
        &mut rpc,
        &crate::shell::CloseInput {
            kind,
            label: &target.label,
            subject: &session.user.sub,
            terminal_id,
            environment_id: &target.environment_id,
        },
    );
    rpc.transport_mut().shutdown();

    let outcome = outcome.map_err(CliError::of)?;
    writeln!(out, "{}", crate::shell::describe_close_outcome(kind, outcome, &target.label)).ok();
    Ok(())
}

/// `sv add <pairing-url>` — link the machine this command runs on to the
/// signed-in account, using the single-use pairing URL its environment server
/// printed at startup.
///
/// The order is deliberate: everything that can fail without cost — the URL
/// parse, the session, the discovery — happens before the token exchange,
/// because the exchange burns the single-use token. From there the flow never
/// re-runs an earlier step; the environment token lives in this stack frame
/// and each later failure says the token is spent.
pub fn add_link(context: &Context<'_>, out: &mut dyn Write, pairing_url: &str) -> Result<(), CliError> {
    let fresh_url = "(the environment server prints a new one every time it starts)";
    let target = crate::link::parse_pairing_url(pairing_url).map_err(CliError::of)?;
    let session = context.current_session()?;
    let descriptor = crate::link::discover_environment(context.http, &target).map_err(CliError::of)?;

    // -- the burn: nothing above this line may run again on a retry ---------
    let environment_token = crate::link::exchange_pairing_token(context.http, &target).map_err(CliError::of)?;
    if !environment_token.allows_relay_write() {
        return Err(CliError(
            "This pairing link cannot manage the machine's relay connection: use the pairing URL the environment server prints at startup, or one minted with the Manage-relay (relay:write) scope.".to_string(),
        ));
    }

    let spent = |what: &str, failure: crate::link::StepFailure| {
        CliError(format!(
            "Could not {what} ({}). The pairing token is spent now, so get a fresh pairing URL {fresh_url} and run `sv add` again.",
            failure.0
        ))
    };
    let relay_url = &context.config.relay_url;
    let challenge = crate::link::create_link_challenge(context.http, relay_url, &session.access_token)
        .map_err(|failure| spent("get a link challenge from the Svartal relay", failure))?;
    let proof = crate::link::request_link_proof(
        context.http,
        &target,
        &environment_token.access_token,
        relay_url,
        &challenge,
    )
    .map_err(|failure| spent("get a link proof from the machine", failure))?;
    let linked = crate::link::link_environment(context.http, relay_url, &session.access_token, &proof)
        .map_err(|failure| spent("record the link on the Svartal relay", failure))?;
    if linked.environment_id != descriptor.environment_id {
        return Err(CliError(format!(
            "The relay answered for workspace {}, but this machine is {}. The pairing token is spent now, so get a fresh pairing URL {fresh_url} and run `sv add` again.",
            linked.environment_id, descriptor.environment_id
        )));
    }

    // From here the account-side link exists, so the failures stop blaming the
    // token: a fresh one only repeats a flow that is safe to repeat.
    let tunnel = crate::link::configure_relay(
        context.http,
        &target,
        &environment_token.access_token,
        relay_url,
        &linked,
    )
    .map_err(|failure| {
        CliError(format!(
            "Your account is linked to {}, but the machine could not store the relay configuration ({}). Re-running `sv add` with a fresh pairing token is safe.",
            descriptor.label, failure.0
        ))
    })?;

    let confirmed = api::list_linked_environments(context.http, relay_url, &session.access_token)
        .map(|links| links.iter().any(|link| link.environment_id == descriptor.environment_id));
    if !confirmed.unwrap_or(false) {
        return Err(CliError(format!(
            "The machine was configured, but {} does not show in your environment list. The pairing token is spent now, so if `sv machines` still does not show it, get a fresh pairing URL {fresh_url} and run `sv add` again.",
            descriptor.label
        )));
    }

    writeln!(out, "Linked {} to your Svartal account.", descriptor.label).ok();
    match tunnel {
        crate::link::TunnelReport::Running => {}
        crate::link::TunnelReport::NotInstalled => {
            writeln!(
                out,
                "This machine's tunnel client is not installed yet; the machine will be reachable once it is."
            )
            .ok();
        }
        crate::link::TunnelReport::Unspecified => {
            writeln!(out, "sv shell {} will reach it once its tunnel reports in.", descriptor.label)
                .ok();
        }
    }
    Ok(())
}

pub fn sessions(
    context: &Context<'_>,
    out: &mut dyn Write,
    json: bool,
    machine: Option<&str>,
) -> Result<(), CliError> {
    let loaded = load_view(context)?;
    let selected = match machine {
        None => loaded,
        Some(machine) => view::filter_view_by_machine(&loaded, machine),
    };
    if json {
        writeln!(out, "{}", view::format_sessions_json(&selected)).ok();
        return Ok(());
    }
    writeln!(out, "{}", view::format_sessions_view(&selected)).ok();
    Ok(())
}
