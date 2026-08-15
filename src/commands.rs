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
use crate::store::TokenStorage;
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
pub const NOT_SIGNED_IN: &str = "You are not signed in to Svartal. Run `svartal login`.";

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
    // `svartal login` exists to repair, so a failure here must not stop the
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
        "Every sign-in callback port is in use ({}). Close whatever is holding them and run `svartal login` again.",
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
    let session = context.current_session()?;
    let machines: Vec<Machine> =
        api::list_machines(context.http, &context.config.api_base_url, &session.access_token)
            .map_err(CliError::of)?;
    let links: Vec<LinkRecord> =
        api::list_linked_environments(context.http, &context.config.relay_url, &session.access_token)
            .map_err(CliError::of)?;
    Ok(view::build_machines_view(&machines, &links))
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

/// `svartal shell <machine-or-workspace>`.
///
/// Resolve, connect, then hand the terminal over. The remote shell is
/// deliberately left running when the CLI exits: reattaching is the normal
/// case, and the closing line says so rather than implying the shell was
/// killed.
pub fn shell(
    context: &Context<'_>,
    out: &mut dyn Write,
    target: &str,
    terminal_id: Option<&str>,
) -> Result<(), CliError> {
    let session = context.current_session()?;
    let view = load_view(context)?;
    let target = crate::target::select_shell_target(&view, target).map_err(CliError::of)?;

    let dpop_key =
        crate::dpop::load_or_create_key(&context.config.state_directory).map_err(CliError::of)?;
    let connection = crate::shell::connect_workspace(
        context.http,
        &crate::shell::ConnectInput {
            relay_url: &context.config.relay_url,
            client_id: &context.config.client_id,
            access_token: &session.access_token,
            target: &target,
            dpop_key: &dpop_key,
            client_metadata: crate::shell::cli_client_metadata(),
        },
    )
    .map_err(CliError::of)?;

    let transport = crate::ws::WebSocketTransport::connect(&connection.socket_url).map_err(|error| {
        CliError::of(crate::shell::ShellError::Connection {
            label: target.label.clone(),
            detail: error.to_string(),
        })
    })?;
    let mut rpc = crate::rpc::RpcClient::new(transport);

    let size = crate::terminal::terminal_size();
    let shell_session = crate::shell::open_shell(
        &mut rpc,
        &crate::shell::OpenInput {
            label: &target.label,
            subject: &session.user.sub,
            terminal_id,
            environment_id: &target.environment_id,
            size,
        },
    )
    .map_err(CliError::of)?;

    writeln!(
        out,
        "{}",
        if shell_session.reattached {
            format!("Back in your shell on {} ({}).", target.label, shell_session.cwd)
        } else {
            format!("Shell on {} ({}).", target.label, shell_session.cwd)
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
    writeln!(out, "{}", crate::shell::describe_shell_outcome(&outcome, &target.label)).ok();
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
