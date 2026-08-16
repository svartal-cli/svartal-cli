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
        return Ok(());
    }
    let session = sign_in(context, out)?;
    writeln!(out, "Signed in as {}.", display_name(&session)).ok();
    Ok(())
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
/// trips paid for nothing.
fn load_session_and_view(
    context: &Context<'_>,
) -> Result<(Session, view::MachinesView), CliError> {
    let session = context.current_session()?;
    let machines: Vec<Machine> =
        api::list_machines(context.http, &context.config.api_base_url, &session.access_token)
            .map_err(CliError::of)?;
    let links: Vec<LinkRecord> =
        api::list_linked_environments(context.http, &context.config.relay_url, &session.access_token)
            .map_err(CliError::of)?;
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
