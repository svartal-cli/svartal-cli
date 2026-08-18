//! `sv shell` and `sv claude`: a detached terminal in a Svartal workspace,
//! over the relay.
//!
//! Port of `src/shell.ts`. The path is the one the TypeScript CLI's NOTES.md
//! wrote down: relay token exchange, relay connect, workspace token exchange,
//! WebSocket ticket, then the detached terminal namespace
//! `svartal-shell:<subject>` — or `svartal-claude:<subject>` — then bytes.
//!
//! Two things are worth knowing before reading:
//!
//! * **The terminal outlives the connection.** Dropping the socket detaches;
//!   it does not kill the PTY. That is what makes a lost link recoverable, so
//!   ending a shell is an explicit act (`exit`, Ctrl-D, or `sv close`) and not
//!   a side effect of quitting the CLI.
//! * **The terminal id is derived from the workspace id**, so running the
//!   command twice against the same workspace lands in the same terminal, from
//!   any machine the person signs in on.
//!
//! `sv claude` is the same command with a different namespace and a different
//! backing process. Everything below is shared between the two, because on the
//! wire they are one thing: a detached terminal keyed by the acting subject.
//! What differs is what the workspace starts behind it — a shell, or an
//! interactive Claude session inside the machine broker's runner container,
//! which is the only place a brokered credential may be used.

use std::os::fd::RawFd;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::dpop::{DpopKey, ProofRequest, random_uuid_v4};
use crate::http::HttpTransport;
use crate::relay::{self, ConnectRequest, TokenExchange as RelayTokenExchange};
use crate::rpc::{Exit, Incoming, RpcClient, RpcError, RpcTransport};
use crate::target::ShellTarget;
use crate::terminal::TerminalSize;
use crate::workspace::{
    self, CLI_CLIENT_METADATA, ClientMetadata, TokenExchange as WorkspaceTokenExchange,
};

/// `DETACHED_TERMINAL_THREAD_PREFIX`. A terminal is keyed by
/// `(threadId, terminalId)`; a client with no conversation uses this namespace,
/// which the workspace verifies against the acting session's subject on every
/// call.
pub const DETACHED_TERMINAL_THREAD_PREFIX: &str = "svartal-shell:";
/// `PROVIDER_TERMINAL_THREAD_PREFIX`: the sibling namespace whose terminals are
/// backed by an interactive provider session rather than a shell.
pub const PROVIDER_TERMINAL_THREAD_PREFIX: &str = "svartal-claude:";

/// Which detached terminal a command opens.
///
/// One namespace each, one terminal-id prefix each, one noun each. The two are
/// otherwise the same client: same connect chain, same open, same attach, same
/// byte pump, same reattach. A person can have both at once on one workspace,
/// which is exactly why they are two namespaces and not a flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalKind {
    Shell,
    Claude,
}

impl TerminalKind {
    pub const fn thread_prefix(self) -> &'static str {
        match self {
            Self::Shell => DETACHED_TERMINAL_THREAD_PREFIX,
            Self::Claude => PROVIDER_TERMINAL_THREAD_PREFIX,
        }
    }

    /// The terminal id prefix, so a machine's owner can tell at a glance what
    /// a row in their terminal list is.
    pub const fn terminal_id_prefix(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Claude => "claude",
        }
    }

    /// What this terminal is called in a sentence a person reads.
    pub const fn noun(self) -> &'static str {
        match self {
            Self::Shell => "shell",
            Self::Claude => "Claude terminal",
        }
    }

    /// Capitalized, for the start of a sentence.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Shell => "Shell",
            Self::Claude => "Claude",
        }
    }
}

pub const METHOD_SERVER_GET_CONFIG: &str = "server.getConfig";
pub const METHOD_TERMINAL_OPEN: &str = "terminal.open";
pub const METHOD_TERMINAL_ATTACH: &str = "terminal.attach";
pub const METHOD_TERMINAL_WRITE: &str = "terminal.write";
pub const METHOD_TERMINAL_RESIZE: &str = "terminal.resize";
pub const METHOD_TERMINAL_CLOSE: &str = "terminal.close";
/// The metadata stream whose opening event is a snapshot of every live
/// terminal. `sv close` reads that one event and hangs the stream up: it is
/// the only way this wire can say "nothing is running", because
/// `terminal.close` returns nothing and treats a missing terminal as a no-op.
pub const METHOD_TERMINAL_SUBSCRIBE_METADATA: &str = "subscribeTerminalMetadata";

/// Long enough for a workspace that is busy, short enough that a wedged one
/// does not hold the terminal forever.
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest the pump ever sleeps without looking at anything.
///
/// On a terminal this is a safety net, not the mechanism: the pump waits on the
/// socket and the keyboard together (see `wait_for_activity`) and wakes the
/// moment either has something. It is still bounded, because the WebSocket and
/// TLS layers each keep a buffer of their own, and a frame sitting in one of
/// those makes no descriptor readable.
const PUMP_TICK: Duration = Duration::from_millis(50);

/// The socket wait used when the descriptor says there is nothing to read.
///
/// Not zero: a zero timeout on a socket means "no timeout", i.e. block forever.
/// This is the shortest wait that still lets the WebSocket layer hand up a
/// frame it had already decoded into its own buffer.
const IDLE_TICK: Duration = Duration::from_millis(1);
/// `TerminalWriteInput` caps `data` at 64 KiB.
const MAX_WRITE_BYTES: usize = 65_536;

#[derive(Debug)]
pub enum ShellError {
    /// The only refusal that can be the detached-namespace guard: the connect
    /// step already asked for and was granted `terminal:operate`, so an
    /// authorization refusal on a terminal call is not about scope.
    Namespace { kind: TerminalKind, label: String, subject: String },
    /// The grant does not cover terminals at all. Refused while handing out the
    /// access token, before any terminal call is made.
    TerminalNotAllowed { label: String },
    /// The workspace opened the terminal and could not start what belongs
    /// behind it. `detail` is the workspace's own sentence, kept word for
    /// word: it is the one that says *why* — no authorized Claude credential,
    /// a credential that is not brokered, a machine with no broker at all.
    NotStarted { kind: TerminalKind, label: String, detail: String },
    Connection { kind: TerminalKind, label: String, detail: String },
    /// `sv close` could not finish: the metadata read or the close call itself
    /// failed. Never the "nothing was running" case, which is an answer.
    NotClosed { kind: TerminalKind, label: String, detail: String },
}

impl std::fmt::Display for ShellError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Namespace { kind, label, subject } => write!(
                f,
                "{label} would not open a {noun} for {subject}. It does not agree that this is who you are, so it refused your {noun}. Sign out and sign in again; if it keeps happening, your account and that workspace disagree about your identity.",
                noun = kind.noun()
            ),
            Self::TerminalNotAllowed { label } => write!(
                f,
                "Your grant on {label} does not allow terminals. Ask whoever manages that machine to allow terminal access for your account, then try again."
            ),
            Self::NotStarted { kind, label, detail } => {
                write!(f, "Could not start your {} on {label}: {detail}", kind.noun())
            }
            Self::Connection { kind, label, detail } => {
                write!(f, "Could not open a {} on {label}: {detail}", kind.noun())
            }
            Self::NotClosed { kind, label, detail } => {
                write!(f, "Could not close the {} on {label}: {detail}", kind.noun())
            }
        }
    }
}

impl std::error::Error for ShellError {}

fn connection_error(kind: TerminalKind, label: &str, detail: impl std::fmt::Display) -> ShellError {
    ShellError::Connection { kind, label: label.to_string(), detail: detail.to_string() }
}

/// `EnvironmentAuthorizationError` on a terminal call is the namespace guard;
/// everything else is a connection failure.
fn terminal_call_error(
    error: &RpcError,
    kind: TerminalKind,
    label: &str,
    subject: &str,
) -> ShellError {
    if error.tag() == Some("EnvironmentAuthorizationError") {
        return ShellError::Namespace {
            kind,
            label: label.to_string(),
            subject: subject.to_string(),
        };
    }
    connection_error(kind, label, error)
}

/// `terminal_call_error`, for the close path: the namespace guard keeps its
/// sentence, everything else says "could not close" rather than "could not
/// open".
fn close_call_error(
    error: &RpcError,
    kind: TerminalKind,
    label: &str,
    subject: &str,
) -> ShellError {
    if error.tag() == Some("EnvironmentAuthorizationError") {
        return ShellError::Namespace {
            kind,
            label: label.to_string(),
            subject: subject.to_string(),
        };
    }
    ShellError::NotClosed { kind, label: label.to_string(), detail: error.to_string() }
}

/// The terminal id `sv shell <target>` and `sv claude <target>` use.
///
/// Derived from the workspace id, so it is the same on every run and from every
/// device: reconnecting reattaches instead of piling up abandoned PTYs. It is
/// also distinguishable at a glance from Ivaldi's thread terminals (`term-1`),
/// and from the other kind of detached terminal on the same workspace.
pub fn terminal_id(kind: TerminalKind, environment_id: &str) -> String {
    let mut slug = String::with_capacity(environment_id.len());
    let mut pending_separator = false;
    for character in environment_id.chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            if pending_separator && !slug.is_empty() {
                slug.push('-');
            }
            pending_separator = false;
            slug.push(character);
        } else {
            pending_separator = true;
        }
    }
    let slug = slug.trim_matches('-');
    let id = format!(
        "{}-{}",
        kind.terminal_id_prefix(),
        if slug.is_empty() { "workspace" } else { slug }
    );
    id.chars().take(128).collect()
}

/// `makeDetachedTerminalThreadId` / `makeProviderTerminalThreadId`.
pub fn detached_thread_id(kind: TerminalKind, subject: &str) -> String {
    format!("{}{}", kind.thread_prefix(), subject.trim())
}

// -- the connect chain -----------------------------------------------------

pub struct ConnectInput<'a> {
    /// Only shapes the wording of a failure: the connect chain itself is the
    /// same four requests for both kinds of terminal.
    pub kind: TerminalKind,
    pub relay_url: &'a str,
    pub client_id: &'a str,
    /// The OIDC access token from the local Svartal credential.
    pub access_token: &'a str,
    pub target: &'a ShellTarget,
    pub dpop_key: &'a DpopKey,
    pub client_metadata: ClientMetadata,
    /// What the workspace access token must cover: `SHELL_SCOPES` to open a
    /// terminal, `CLOSE_SCOPES` to end one. Asked for here so a command never
    /// holds a scope it makes no call under.
    pub scopes: &'a [&'a str],
}

#[derive(Debug, Clone)]
pub struct WorkspaceConnection {
    pub socket_url: String,
    pub http_base_url: String,
    pub access_token: String,
}

/// Relay exchange, relay connect, workspace token exchange, WebSocket ticket.
///
/// Every step is DPoP-bound and the proofs are per-request: one is signed for
/// each URL, and the two that present a token carry its `ath`.
pub fn connect_workspace(
    http: &dyn HttpTransport,
    input: &ConnectInput<'_>,
) -> Result<WorkspaceConnection, ShellError> {
    let label = input.target.label.as_str();
    let kind = input.kind;
    let proof = |url: &str, access_token: Option<&str>| -> Result<String, ShellError> {
        let jti = random_uuid_v4().map_err(|error| connection_error(kind, label, error))?;
        input
            .dpop_key
            .create_proof(&ProofRequest::now("POST", url, access_token, &jti))
            .map_err(|error| connection_error(kind, label, error))
    };

    let relay_token_url = relay::token_url(input.relay_url);
    let relay_token = relay::exchange_access_token(
        http,
        &RelayTokenExchange {
            relay_url: input.relay_url,
            client_id: input.client_id,
            subject_token: input.access_token,
            dpop_proof: &proof(&relay_token_url, None)?,
        },
    )
    .map_err(|error| connection_error(kind, label, error))?;

    let connect_url = relay::connect_url(input.relay_url, &input.target.environment_id);
    let connection = relay::connect_environment(
        http,
        &ConnectRequest {
            relay_url: input.relay_url,
            environment_id: &input.target.environment_id,
            label,
            access_token: &relay_token.access_token,
            // A resource request, so the proof is bound to the token presented
            // with it.
            dpop_proof: &proof(&connect_url, Some(&relay_token.access_token))?,
            thumbprint: input.dpop_key.thumbprint(),
            device_id: None,
        },
    )
    .map_err(|error| connection_error(kind, label, error))?;

    let http_base_url = connection.endpoint.http_base_url.clone();
    let ws_base_url = if connection.endpoint.ws_base_url.trim().is_empty() {
        workspace::default_ws_base_url(&http_base_url).map_err(|error| connection_error(kind, label, error))?
    } else {
        connection.endpoint.ws_base_url.clone()
    };

    let token_url =
        workspace::token_url(&http_base_url).map_err(|error| connection_error(kind, label, error))?;
    let workspace_token = workspace::exchange_access_token(
        http,
        &WorkspaceTokenExchange {
            http_base_url: &http_base_url,
            label,
            credential: &connection.credential,
            scopes: input.scopes,
            dpop_proof: &proof(&token_url, None)?,
            client_metadata: input.client_metadata,
        },
    )
    .map_err(|error| match error {
        // The grant's own refusal keeps its own sentence, rather than being
        // wrapped in "could not open a terminal".
        workspace::WorkspaceError::TerminalNotAllowed { label } => {
            ShellError::TerminalNotAllowed { label }
        }
        other => connection_error(kind, label, other),
    })?;

    let ticket_url = workspace::websocket_ticket_url(&http_base_url)
        .map_err(|error| connection_error(kind, label, error))?;
    let ticket = workspace::issue_websocket_ticket(
        http,
        &http_base_url,
        label,
        &workspace_token.access_token,
        // Bound to the access token this request carries: the workspace
        // verifies the proof's `ath` against it.
        &proof(&ticket_url, Some(&workspace_token.access_token))?,
    )
    .map_err(|error| connection_error(kind, label, error))?;

    Ok(WorkspaceConnection {
        socket_url: workspace::websocket_url(&ws_base_url, &ticket.ticket)
            .map_err(|error| connection_error(kind, label, error))?,
        http_base_url,
        access_token: workspace_token.access_token,
    })
}

// -- the terminal ----------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ShellSession {
    pub kind: TerminalKind,
    pub thread_id: String,
    pub terminal_id: String,
    pub cwd: String,
    /// The `TERM` this session was opened with, replayed on every reattach.
    pub term: Option<String>,
    /// The `COLORTERM` this session was opened with, replayed on every reattach.
    pub colorterm: Option<String>,
    /// True when an existing terminal was picked back up rather than started.
    pub reattached: bool,
}

pub struct OpenInput<'a> {
    pub kind: TerminalKind,
    pub label: &'a str,
    /// The verified subject; the namespace this person's terminals live in.
    pub subject: &'a str,
    pub terminal_id: Option<&'a str>,
    pub environment_id: &'a str,
    pub size: TerminalSize,
    /// This terminal's own `TERM`, so the remote PTY is spawned as the terminal
    /// the person is looking at rather than a fixed guess. `None` leaves the
    /// workspace on its own default.
    pub term: Option<String>,
    /// This terminal's own `COLORTERM`, so a program on the far side knows
    /// whether 24-bit colour renders here. `None` means the workspace sets
    /// none either: there is no default to fall back to.
    pub colorterm: Option<String>,
}

/// The allowlist the workspace's terminal contract enforces on `term`.
///
/// The value becomes an environment variable in a process on someone else's
/// machine, so the CLI does not forward whatever `$TERM` happens to hold: only
/// letters, digits, and the four characters terminfo names use. Anything else
/// is not sent, and the workspace uses its default.
pub fn accepted_term(value: Option<&str>) -> Option<String> {
    let term = value?.trim();
    if term.is_empty() || term.len() > 64 {
        return None;
    }
    let accepted = term
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-'));
    accepted.then(|| term.to_string())
}

/// This process's `TERM`, when it is one the workspace accepts.
pub fn local_term() -> Option<String> {
    accepted_term(std::env::var("TERM").ok().as_deref())
}

/// The allowlist the workspace's terminal contract enforces on `colorterm`.
///
/// The same reasoning as `accepted_term`, with a lower ceiling: the values in
/// use are short words (`truecolor`, `24bit`), not terminfo names.
pub fn accepted_colorterm(value: Option<&str>) -> Option<String> {
    let colorterm = value?.trim();
    if colorterm.is_empty() || colorterm.len() > 32 {
        return None;
    }
    let accepted = colorterm
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '+' | '-'));
    accepted.then(|| colorterm.to_string())
}

/// This process's `COLORTERM`, when it is one the workspace accepts.
///
/// `TERM` names a terminfo entry; `COLORTERM` is the separate convention that
/// says "this terminal really renders 24-bit colour", and agent TUIs read it
/// before they emit truecolour escapes. Sending nothing is a real answer: the
/// workspace has no default, because claiming truecolour for a terminal that
/// cannot do it makes programs print escape sequences as literal text.
pub fn local_colorterm() -> Option<String> {
    accepted_colorterm(std::env::var("COLORTERM").ok().as_deref())
}

/// Add an optional string field to a terminal call's payload when there is one
/// to send. An absent value sends no key at all, not an explicit null.
fn with_optional(mut payload: Value, key: &str, value: Option<&str>) -> Value {
    if let (Some(value), Some(object)) = (value, payload.as_object_mut()) {
        object.insert(key.to_string(), Value::String(value.to_string()));
    }
    payload
}

/// Add `term` and `colorterm` to a terminal call's payload.
fn with_terminal_description(
    payload: Value,
    term: Option<&str>,
    colorterm: Option<&str>,
) -> Value {
    with_optional(with_optional(payload, "term", term), "colorterm", colorterm)
}

/// Whether the workspace handed back a terminal that was already running.
///
/// The workspace answers this itself, in `created`: it either spawned a process
/// or found one, and it is the only party that can tell the two apart. The
/// branch below it is what this CLI had to do before that field existed, kept
/// only for a workspace image that has not been updated yet.
///
/// That old guess is wrong, and visibly so. A freshly spawned PTY is reported
/// `running` with a pid within milliseconds, so "running with a pid" is true of
/// a shell that has never existed before — every new terminal was greeted with
/// "Back in your shell". A provider terminal has no local pid at all, so there
/// the guess degraded further, to "running at all", which is true of every
/// provider terminal the moment it starts.
///
/// It stays as a fallback because the alternative is worse: against an older
/// workspace, reading a missing field as "not reattached" would tell a person
/// their long-running Claude session is a new one.
fn was_reattached(snapshot: &Value, kind: TerminalKind) -> bool {
    if let Some(created) = snapshot.get("created").and_then(Value::as_bool) {
        return !created;
    }
    let running = snapshot.get("status").and_then(Value::as_str) == Some("running");
    running
        && (kind == TerminalKind::Claude
            || snapshot.get("pid").is_some_and(|pid| !pid.is_null()))
}

/// Read the workspace's config for the root to open in, then open (or pick up)
/// this person's terminal there.
pub fn open_shell<T: RpcTransport>(
    rpc: &mut RpcClient<T>,
    input: &OpenInput<'_>,
) -> Result<ShellSession, ShellError> {
    let kind = input.kind;
    let config = rpc
        .call(METHOD_SERVER_GET_CONFIG, json!({}), CALL_TIMEOUT)
        .map_err(|error| connection_error(kind, input.label, error))?;
    // The workspace root, reported by the workspace. The CLI never guesses one.
    let cwd = config
        .get("cwd")
        .and_then(Value::as_str)
        .filter(|cwd| !cwd.trim().is_empty())
        .ok_or_else(|| {
            connection_error(kind, input.label, "the workspace did not report its root.")
        })?
        .to_string();

    let terminal_id = input
        .terminal_id
        .map(str::to_string)
        .unwrap_or_else(|| terminal_id(kind, input.environment_id));
    let thread_id = detached_thread_id(kind, input.subject);
    let snapshot = rpc
        .call(
            METHOD_TERMINAL_OPEN,
            with_terminal_description(
                json!({
                    "threadId": thread_id,
                    "terminalId": terminal_id,
                    "cwd": cwd,
                    "cols": input.size.cols,
                    "rows": input.size.rows,
                }),
                input.term.as_deref(),
                input.colorterm.as_deref(),
            ),
            CALL_TIMEOUT,
        )
        .map_err(|error| terminal_call_error(&error, kind, input.label, input.subject))?;

    // The workspace opened the terminal and could not start what belongs
    // behind it — no authorized Claude credential, a credential that is not
    // brokered, a machine with no broker. The reason is on the terminal's own
    // screen, and it is the only useful thing to say, so it is said as-is.
    if snapshot.get("status").and_then(Value::as_str) == Some("error") {
        return Err(ShellError::NotStarted {
            kind,
            label: input.label.to_string(),
            detail: last_terminal_message(&snapshot),
        });
    }

    let reattached = was_reattached(&snapshot, kind);
    Ok(ShellSession {
        kind,
        thread_id,
        terminal_id,
        cwd,
        term: input.term.clone(),
        colorterm: input.colorterm.clone(),
        reattached,
    })
}

/// The last thing a terminal printed, which for a terminal that failed to
/// start is the workspace's own explanation.
fn last_terminal_message(snapshot: &Value) -> String {
    snapshot
        .get("history")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("the workspace did not say why.")
        .to_string()
}

/// How a terminal ended, so the caller can say the right sentence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellOutcome {
    Exited { exit_code: Option<i64> },
    Closed,
    Detached,
}

/// The line printed when a terminal ends, in the same plain words for each way.
pub fn describe_shell_outcome(kind: TerminalKind, outcome: &ShellOutcome, label: &str) -> String {
    let title = kind.title();
    let noun = kind.noun();
    match outcome {
        ShellOutcome::Exited { exit_code: None | Some(0) } => {
            format!("{title} on {label} ended.")
        }
        ShellOutcome::Exited { exit_code: Some(code) } => {
            format!("{title} on {label} ended with status {code}.")
        }
        ShellOutcome::Closed => format!("{title} on {label} was closed."),
        ShellOutcome::Detached => {
            format!("Left the {noun} on {label} running. Run the same command to pick it up again.")
        }
    }
}

// -- closing from outside --------------------------------------------------

/// What `sv close` found on the workspace. Both are answers, not failures:
/// asking to end a terminal that is not running deserves a sentence, not a
/// stack of refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseOutcome {
    Closed,
    NothingRunning,
}

/// The line `sv close` prints, one sentence per answer the wire can give.
pub fn describe_close_outcome(kind: TerminalKind, outcome: CloseOutcome, label: &str) -> String {
    let noun = kind.noun();
    match outcome {
        CloseOutcome::Closed => format!("Closed the {noun} on {label}."),
        CloseOutcome::NothingRunning => format!("No {noun} was running on {label}."),
    }
}

pub struct CloseInput<'a> {
    pub kind: TerminalKind,
    pub label: &'a str,
    /// The verified subject; the namespace this person's terminals live in.
    pub subject: &'a str,
    pub terminal_id: Option<&'a str>,
    pub environment_id: &'a str,
}

/// End this person's terminal on the workspace, or learn that none is running.
///
/// `terminal.close` answers the same nothing whether it killed a PTY or found
/// no session — the workspace treats a missing terminal as a no-op — so the
/// call alone cannot say which sentence the person should read. The metadata
/// stream can: its opening event is a snapshot of every live terminal. So:
/// read that snapshot, hang the stream up, and send the close only for a
/// terminal that is there. The `terminalId` is always sent, because a close
/// without one ends every terminal in the thread, and this command was asked
/// about one.
pub fn close_shell<T: RpcTransport>(
    rpc: &mut RpcClient<T>,
    input: &CloseInput<'_>,
) -> Result<CloseOutcome, ShellError> {
    let kind = input.kind;
    let terminal_id = input
        .terminal_id
        .map(str::to_string)
        .unwrap_or_else(|| terminal_id(kind, input.environment_id));
    let thread_id = detached_thread_id(kind, input.subject);

    if !terminal_is_running(rpc, input, &thread_id, &terminal_id)? {
        return Ok(CloseOutcome::NothingRunning);
    }

    rpc.call(
        METHOD_TERMINAL_CLOSE,
        json!({ "threadId": thread_id, "terminalId": terminal_id }),
        CALL_TIMEOUT,
    )
    .map_err(|error| close_call_error(&error, kind, input.label, input.subject))?;
    Ok(CloseOutcome::Closed)
}

/// Whether `(thread_id, terminal_id)` is in the metadata stream's opening
/// snapshot: subscribe, read the one event, interrupt the stream.
fn terminal_is_running<T: RpcTransport>(
    rpc: &mut RpcClient<T>,
    input: &CloseInput<'_>,
    thread_id: &str,
    terminal_id: &str,
) -> Result<bool, ShellError> {
    let kind = input.kind;
    let fail = |error: &RpcError| close_call_error(error, kind, input.label, input.subject);
    let subscription =
        rpc.request(METHOD_TERMINAL_SUBSCRIBE_METADATA, json!({})).map_err(|error| fail(&error))?;
    let deadline = Instant::now() + CALL_TIMEOUT;
    loop {
        if Instant::now() >= deadline {
            let _ = rpc.interrupt(&subscription);
            return Err(fail(&RpcError::Timeout));
        }
        for message in rpc.pump(Duration::from_millis(100)).map_err(|error| fail(&error))? {
            match message {
                Incoming::Chunk { ref request_id, ref values } if *request_id == subscription => {
                    let Some(snapshot) = values
                        .iter()
                        .find(|event| event.get("type").and_then(Value::as_str) == Some("snapshot"))
                    else {
                        continue;
                    };
                    let running = snapshot
                        .get("terminals")
                        .and_then(Value::as_array)
                        .is_some_and(|terminals| {
                            terminals.iter().any(|terminal| {
                                terminal.get("threadId").and_then(Value::as_str) == Some(thread_id)
                                    && terminal.get("terminalId").and_then(Value::as_str)
                                        == Some(terminal_id)
                            })
                        });
                    let _ = rpc.interrupt(&subscription);
                    return Ok(running);
                }
                Incoming::Exit { ref request_id, ref exit } if *request_id == subscription => {
                    // The stream ended before its snapshot. Whatever the cause
                    // carries is the reason; a clean end with no snapshot has
                    // no reason to give.
                    let error = match exit {
                        Exit::Failure(cause) => RpcError::Failed(first_error(cause)),
                        Exit::Success(_) => RpcError::Transport(
                            "the workspace ended the terminal listing before sending it."
                                .to_string(),
                        ),
                    };
                    return Err(fail(&error));
                }
                Incoming::Defect(defect) => return Err(fail(&RpcError::Defect(defect))),
                _ => {}
            }
        }
    }
}

/// The local half of the byte pump, as data a test can supply.
pub trait LocalTerminal {
    fn size(&self) -> TerminalSize;
    fn write(&mut self, data: &str);
    /// Bytes typed since the last call, or `None` when local input ended.
    fn take_input(&mut self) -> InputPoll;
    /// True once per local resize.
    fn take_resize(&mut self) -> bool;
    /// A descriptor that becomes readable when `take_input` has something.
    ///
    /// `None` — every test terminal — keeps the old behaviour: the pump waits
    /// on the socket alone and picks input up on the next tick.
    fn ready_fd(&self) -> Option<RawFd> {
        None
    }
}

/// Wait until the socket has data, local input is waiting, or the timeout runs
/// out. Returns whether the *socket* is the one that has something.
///
/// This is the whole of the typing-latency fix on the client. A loop that
/// blocks on the socket and then checks the keyboard adds its own wait to every
/// keystroke — half the tick on average, a whole tick at worst. Waiting on both
/// descriptors at once adds nothing at all.
///
/// A `poll` that fails is reported as "read the socket", which is exactly the
/// behaviour this replaced, so an error here costs latency and never
/// correctness.
pub fn wait_for_activity(socket: RawFd, input: RawFd, timeout: Duration) -> bool {
    let mut fds = [
        libc::pollfd { fd: socket, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: input, events: libc::POLLIN, revents: 0 },
    ];
    let millis = libc::c_int::try_from(timeout.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: `poll` reads and writes the two-element array we own, for the
    // length passed, and does not retain it.
    let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, millis) };
    if ready < 0 {
        return true;
    }
    fds[0].revents != 0
}

pub enum InputPoll {
    None,
    Data(String),
    Ended,
}

pub struct PumpInput<'a> {
    pub session: &'a ShellSession,
    pub label: &'a str,
    pub subject: &'a str,
}

/// Run the byte pump until the remote terminal ends or local input closes.
///
/// One loop owns the socket: it reads what the workspace sent, writes what was
/// typed, and resizes. Local input closing is a detach, not a failure — the
/// remote terminal keeps running.
pub fn run_shell_pump<T: RpcTransport>(
    rpc: &mut RpcClient<T>,
    terminal: &mut dyn LocalTerminal,
    input: &PumpInput<'_>,
) -> Result<ShellOutcome, ShellError> {
    let size = terminal.size();
    let attach_id = rpc
        .request(
            METHOD_TERMINAL_ATTACH,
            with_terminal_description(
                json!({
                    "threadId": input.session.thread_id,
                    "terminalId": input.session.terminal_id,
                    "cols": size.cols,
                    "rows": size.rows,
                }),
                input.session.term.as_deref(),
                input.session.colorterm.as_deref(),
            ),
        )
        .map_err(|error| terminal_call_error(&error, input.session.kind, input.label, input.subject))?;

    let outcome = pump_until_end(rpc, terminal, input, &attach_id);
    // Tell the workspace to stop streaming. The reference client sends this
    // when it tears the subscription down, and a workspace that keeps a dead
    // stream open keeps buffering for it.
    let _ = rpc.interrupt(&attach_id);
    outcome
}

fn pump_until_end<T: RpcTransport>(
    rpc: &mut RpcClient<T>,
    terminal: &mut dyn LocalTerminal,
    input: &PumpInput<'_>,
    attach_id: &str,
) -> Result<ShellOutcome, ShellError> {
    let mut outcome = ShellOutcome::Detached;
    // Both halves have to expose a descriptor for the combined wait; a test
    // transport or a test terminal exposes neither, and falls back to the tick.
    let waitable = rpc.readable_fd().zip(terminal.ready_fd());
    loop {
        rpc.ping_if_due().map_err(|error| connection_error(input.session.kind, input.label, error))?;

        let socket_wait = match waitable {
            None => PUMP_TICK,
            Some((socket, ready)) => {
                if wait_for_activity(socket, ready, PUMP_TICK) { PUMP_TICK } else { IDLE_TICK }
            }
        };
        let messages = rpc.pump(socket_wait).map_err(|error| connection_error(input.session.kind, input.label, error))?;
        for message in messages {
            match message {
                Incoming::Chunk { ref request_id, ref values } if request_id == attach_id => {
                    for event in values {
                        if let Some(ended) = apply_terminal_event(terminal, event) {
                            outcome = ended;
                            return Ok(outcome);
                        }
                    }
                }
                Incoming::Exit { ref request_id, ref exit } => {
                    if let Exit::Failure(cause) = exit {
                        let error = crate::rpc::RpcError::Failed(first_error(cause));
                        return Err(terminal_call_error(&error, input.session.kind, input.label, input.subject));
                    }
                    // The attach stream ending without an exit event is a
                    // detach: the PTY is still there.
                    if request_id == attach_id {
                        return Ok(outcome);
                    }
                }
                Incoming::Defect(defect) => {
                    return Err(connection_error(input.session.kind, input.label, crate::rpc::describe_error(&defect)));
                }
                _ => {}
            }
        }

        match terminal.take_input() {
            InputPoll::None => {}
            InputPoll::Ended => return Ok(ShellOutcome::Detached),
            InputPoll::Data(data) => {
                for chunk in split_write(&data) {
                    rpc.request(
                        METHOD_TERMINAL_WRITE,
                        json!({
                            "threadId": input.session.thread_id,
                            "terminalId": input.session.terminal_id,
                            "data": chunk,
                        }),
                    )
                    .map_err(|error| terminal_call_error(&error, input.session.kind, input.label, input.subject))?;
                }
            }
        }

        if terminal.take_resize() {
            let size = terminal.size();
            rpc.request(
                METHOD_TERMINAL_RESIZE,
                json!({
                    "threadId": input.session.thread_id,
                    "terminalId": input.session.terminal_id,
                    "cols": size.cols,
                    "rows": size.rows,
                }),
            )
            .map_err(|error| terminal_call_error(&error, input.session.kind, input.label, input.subject))?;
        }
    }
}

/// Returns the outcome when this event ends the shell.
fn apply_terminal_event(terminal: &mut dyn LocalTerminal, event: &Value) -> Option<ShellOutcome> {
    match event.get("type").and_then(Value::as_str) {
        Some("snapshot") => {
            // Replayed history: what the shell looked like before this client
            // arrived. On a fresh PTY it is empty.
            let history = event
                .get("snapshot")
                .and_then(|snapshot| snapshot.get("history"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !history.is_empty() {
                terminal.write(history);
            }
            None
        }
        Some("output") => {
            if let Some(data) = event.get("data").and_then(Value::as_str) {
                terminal.write(data);
            }
            None
        }
        Some("exited") => {
            Some(ShellOutcome::Exited { exit_code: event.get("exitCode").and_then(Value::as_i64) })
        }
        Some("closed") => Some(ShellOutcome::Closed),
        Some("error") => {
            let message = event.get("message").and_then(Value::as_str).unwrap_or_default();
            terminal.write(&format!("\r\n{message}\r\n"));
            Some(ShellOutcome::Closed)
        }
        // `cleared`, `restarted`, `activity`: nothing to draw, nothing ended.
        _ => None,
    }
}

fn first_error(cause: &Value) -> Value {
    cause
        .as_array()
        .and_then(|entries| entries.first())
        .and_then(|entry| entry.get("error").or_else(|| entry.get("defect")))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The workspace caps one write at 64 KiB, and a paste can be larger.
fn split_write(data: &str) -> Vec<String> {
    if data.len() <= MAX_WRITE_BYTES {
        return vec![data.to_string()];
    }
    let mut chunks = Vec::new();
    let mut current = String::new();
    for character in data.chars() {
        if current.len() + character.len_utf8() > MAX_WRITE_BYTES {
            chunks.push(std::mem::take(&mut current));
        }
        current.push(character);
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

/// The metadata the workspace's session list shows for this client.
pub const fn cli_client_metadata() -> ClientMetadata {
    CLI_CLIENT_METADATA
}
