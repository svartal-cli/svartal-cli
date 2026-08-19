//! `sv ssh-proxy` and `sv ssh-setup`: one SSH connection's bytes, carried to a
//! Svartal workspace, and the local files that make `ssh svartal-<name>` work.
//!
//! The wire contract is ivaldi's
//! `packages/svartal-client/docs/ssh-bridge.md` (`svartal-ssh.v1`), and it is
//! frozen: this module is written against that document, not against the
//! TypeScript client, and `tests/ssh_proxy.rs` replays a transcript recorded
//! from that client to prove the two agree byte for byte.
//!
//! `ssh-proxy` is an SSH client's transport, not an ordinary command, and that
//! constrains it more than anything else in this binary (doc §8):
//!
//! 1. **stdout carries payload bytes and nothing else.** Not a progress line,
//!    not a warning, not a newline. Every diagnostic goes to stderr, where
//!    `ssh` passes it through to the person's terminal.
//! 2. **The host key is written before a single byte is pumped.** `READY`
//!    carries it over a channel that is already DPoP-authenticated and TLS
//!    protected, and the `ProxyCommand` starts before key exchange does.
//! 3. **Stdin EOF is a half-close, not an end.** `ssh host 'cat > file' < local`
//!    ends its input while it is still reading output.
//! 4. **The exit status is the only diagnostic channel left** once the pump has
//!    started: `ssh` reports a `ProxyCommand` that dies as a broken connection.
//! 5. **Terminal modes are never touched.** stdin and stdout are pipes from
//!    `ssh`, not a terminal, so there is no `RawMode` here and no `SIGWINCH`.
//!
//! The framing is `brok`'s `svartal-pty.v1` grammar with a fresh type table:
//! one type byte, a `u32` big-endian length, then the payload, and a websocket
//! message is not a frame boundary in either direction.

use std::io::Write as _;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime};

use serde_json::{Value, json};

use crate::config::Environment;
use crate::dpop::{DpopKey, ProofRequest, random_uuid_v4};
use crate::http::HttpTransport;
use crate::relay::{self, ConnectRequest, TokenExchange as RelayTokenExchange};
use crate::rpc::TransportError;
use crate::shell::wait_for_activity;
use crate::target::ShellTarget;
use crate::workspace::{self, ClientMetadata, SSH_SCOPES, TokenExchange as WorkspaceTokenExchange};
use crate::ws::BinaryTransport;

/// `SSH_BRIDGE_ROUTE_PATH`. The bridge is a route, not a port.
pub const SSH_ROUTE_PATH: &str = "/ssh";
/// `OPEN.version`. A revision that changes the framing takes a new one.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest payload in one frame, either direction (`0x00010000`).
pub const MAX_FRAME_PAYLOAD: usize = 65_536;
/// One type byte plus a uint32 big-endian length.
pub const FRAME_HEADER_BYTES: usize = 5;

// Client -> server.
pub const FRAME_OPEN: u8 = 0x01;
pub const FRAME_STDIN: u8 = 0x02;
pub const FRAME_STDIN_EOF: u8 = 0x03;
pub const FRAME_CLOSE: u8 = 0x04;
pub const FRAME_PING: u8 = 0x05;
// Server -> client.
pub const FRAME_READY: u8 = 0x81;
pub const FRAME_STDOUT: u8 = 0x82;
pub const FRAME_EXIT: u8 = 0x83;
pub const FRAME_PONG: u8 = 0x85;

/// Doc §4.2: an application-level ping, every five seconds.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);
/// A connection that ended without a status of its own exits non-zero.
pub const GENERIC_EXIT_CODE: i32 = 1;
/// What this client calls itself in the connections view. No authority.
pub const CLIENT_NAME: &str = "sv";

/// The longest the pump ever sleeps without looking at anything, and the wait
/// used when the descriptor says the socket has nothing. Both are `shell.rs`'s,
/// for the same reasons: the WebSocket and TLS layers each keep a buffer that
/// makes no descriptor readable, and a zero socket timeout means "block".
const PUMP_TICK: Duration = Duration::from_millis(50);
const IDLE_TICK: Duration = Duration::from_millis(1);

// -- errors ----------------------------------------------------------------

#[derive(Debug)]
pub enum SshError {
    /// The connect chain, or the socket itself, did not get this client to a
    /// workspace.
    Connect { label: String, detail: String },
    /// The far end broke the framing or the frame order.
    Protocol { label: String, detail: String },
    /// The host key from `READY` could not be recorded, so `ssh` would have no
    /// key to check the workspace against.
    KnownHosts { path: String, detail: String },
    /// The grant does not cover terminals at all. Refused while handing out the
    /// access token, before any frame is sent.
    TerminalNotAllowed { label: String },
    /// `sv ssh-setup` could not write what it was asked to write.
    Setup { detail: String },
}

impl std::fmt::Display for SshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect { label, detail } => {
                write!(f, "Could not open an ssh connection to {label}: {detail}")
            }
            Self::Protocol { label, detail } => {
                write!(f, "The ssh bridge on {label} broke the protocol: {detail}")
            }
            Self::KnownHosts { path, detail } => {
                write!(
                    f,
                    "Could not record the workspace's host key in {path}: {detail}"
                )
            }
            Self::TerminalNotAllowed { label } => write!(
                f,
                "Your grant on {label} does not allow terminals. Ask whoever manages that machine to allow terminal access for your account, then try again."
            ),
            Self::Setup { detail } => write!(f, "{detail}"),
        }
    }
}

impl std::error::Error for SshError {}

fn connect_error(label: &str, detail: impl std::fmt::Display) -> SshError {
    SshError::Connect {
        label: label.to_string(),
        detail: detail.to_string(),
    }
}

fn protocol_error(label: &str, detail: impl std::fmt::Display) -> SshError {
    SshError::Protocol {
        label: label.to_string(),
        detail: detail.to_string(),
    }
}

fn setup_error(detail: impl std::fmt::Display) -> SshError {
    SshError::Setup {
        detail: detail.to_string(),
    }
}

// -- the codec -------------------------------------------------------------

/// One framed message. `kind` is one of the `FRAME_*` constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
}

pub fn encode_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len());
    encoded.push(kind);
    encoded.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

/// `STDIN` for arbitrary bytes, split at the payload ceiling.
///
/// One read off a pipe can be far larger than one frame — an SSH client
/// pushing a file through `scp` fills whatever buffer it is given — so the
/// ceiling is something the encoder handles, not something to hope does not
/// happen.
pub fn encode_stdin_frames(data: &[u8]) -> Vec<Vec<u8>> {
    data.chunks(MAX_FRAME_PAYLOAD)
        .map(|chunk| encode_frame(FRAME_STDIN, chunk))
        .collect()
}

/// `OPEN`, the first client frame, always.
///
/// The field order is the TypeScript reference's, because the fixture pins the
/// bytes: `publicKey`, then `clientName` when there is one, then `version`.
pub fn encode_open_frame(public_key: &str, client_name: Option<&str>) -> Vec<u8> {
    let mut payload = serde_json::Map::new();
    payload.insert(
        "publicKey".to_string(),
        Value::String(public_key.to_string()),
    );
    if let Some(name) = client_name {
        payload.insert("clientName".to_string(), Value::String(name.to_string()));
    }
    payload.insert("version".to_string(), json!(PROTOCOL_VERSION));
    encode_frame(FRAME_OPEN, Value::Object(payload).to_string().as_bytes())
}

/// Turns a byte stream into frames.
///
/// A websocket message is not a frame boundary: a header can arrive one byte at
/// a time and a payload can arrive in twenty pieces, while another message
/// carries four whole frames and half of a fifth. The decoder keeps whatever it
/// cannot yet complete and hands back only the frames it has in full.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    pending: Vec<u8>,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes held back because their frame is not complete yet.
    pub fn buffered(&self) -> usize {
        self.pending.len()
    }

    /// `Err` is a peer that broke the framing; the frames that were complete
    /// before it are lost with it, because the connection ends either way.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, String> {
        self.pending.extend_from_slice(chunk);
        let mut frames = Vec::new();
        let mut offset = 0;
        while self.pending.len() - offset >= FRAME_HEADER_BYTES {
            let header = &self.pending[offset..offset + FRAME_HEADER_BYTES];
            let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
            if length > MAX_FRAME_PAYLOAD {
                // Stop before allocating anything: the peer is either broken or
                // not speaking this protocol, and both are the same answer.
                self.pending.clear();
                return Err("a frame larger than the protocol's payload ceiling".to_string());
            }
            let end = offset + FRAME_HEADER_BYTES + length;
            if self.pending.len() < end {
                break;
            }
            frames.push(Frame {
                kind: header[0],
                payload: self.pending[offset + FRAME_HEADER_BYTES..end].to_vec(),
            });
            offset = end;
        }
        if offset > 0 {
            self.pending.drain(..offset);
        }
        Ok(frames)
    }
}

/// `READY`, the first server frame, always.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub connection_id: String,
    pub host_public_key: String,
}

/// `EXIT`: the sshd is gone, and this is why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitFrame {
    pub reason: String,
    /// `None` for a connection that ended without a status of its own.
    pub exit_code: Option<i64>,
}

fn trimmed_string(value: Option<&Value>, field: &str) -> Result<String, String> {
    let text = value.and_then(Value::as_str).unwrap_or_default().trim();
    if text.is_empty() {
        return Err(format!("{field} is missing"));
    }
    Ok(text.to_string())
}

pub fn decode_ready(payload: &[u8]) -> Result<Ready, String> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|error| format!("a READY frame this client cannot read: {error}"))?;
    Ok(Ready {
        connection_id: trimmed_string(value.get("connectionId"), "connectionId")?,
        host_public_key: trimmed_string(value.get("hostPublicKey"), "hostPublicKey")?,
    })
}

pub fn decode_exit(payload: &[u8]) -> Result<ExitFrame, String> {
    let value: Value = serde_json::from_slice(payload)
        .map_err(|error| format!("an EXIT frame this client cannot read: {error}"))?;
    let exit_code = match value.get("exitCode") {
        None | Some(Value::Null) => None,
        Some(code) => Some(
            code.as_i64()
                .ok_or_else(|| "exitCode is not a number".to_string())?,
        ),
    };
    Ok(ExitFrame {
        reason: trimmed_string(value.get("reason"), "reason")?,
        exit_code,
    })
}

/// The status this process exits with (doc §8.5).
///
/// `EXIT.exitCode` when it is a usable one, a non-zero status otherwise: a
/// connection killed by a signal, torn down by the server, or refused for a
/// protocol reason did not succeed, and `ssh` has nowhere else to learn that
/// from.
pub fn exit_status_for(reason: &str, exit_code: Option<i64>) -> i32 {
    if reason != "sshd_exited" {
        return GENERIC_EXIT_CODE;
    }
    match exit_code {
        Some(code) if (0..=255).contains(&code) => code as i32,
        _ => GENERIC_EXIT_CODE,
    }
}

// -- the local end ---------------------------------------------------------

/// What the local reader saw. Bytes, never a `String`: an SSH binary packet is
/// not text, and `Utf8Chunker` would turn a lone `0xff` into U+FFFD.
pub enum InputPoll {
    None,
    Data(Vec<u8>),
    /// Local input ended — the half-close, not the end of the connection.
    Ended,
}

/// The pipes `ssh` handed this process.
pub trait ProxyStdio {
    fn take_input(&mut self) -> InputPoll;
    /// Payload bytes to stdout. Nothing else is ever written there.
    fn write(&mut self, bytes: &[u8]);
    /// A descriptor that becomes readable when `take_input` has something.
    fn ready_fd(&self) -> Option<RawFd> {
        None
    }
}

enum ReaderMessage {
    Data(Vec<u8>),
    Ended,
}

/// This process's stdin and stdout, as the transport's two pipes.
///
/// The same reader-thread and signal-pipe shape `terminal.rs` uses, minus the
/// UTF-8 chunking: the pump waits on the socket and on stdin together, so a
/// byte from either wakes it immediately.
pub struct ProcessStdio {
    input: Receiver<ReaderMessage>,
    ready: Option<OwnedFd>,
    ended: bool,
}

impl Default for ProcessStdio {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessStdio {
    pub fn new() -> Self {
        let (sender, receiver): (Sender<ReaderMessage>, Receiver<ReaderMessage>) = channel();
        let (ready, notify) = match crate::terminal::signal_pipe() {
            Some((read, write)) => (Some(read), Some(write)),
            None => (None, None),
        };
        std::thread::spawn(move || {
            let notify = notify;
            let wake = || {
                if let Some(fd) = notify.as_ref() {
                    crate::terminal::signal(fd.as_raw_fd());
                }
            };
            let mut buffer = [0u8; 32_768];
            loop {
                // SAFETY: reading into a buffer we own, on the descriptor this
                // thread is the only reader of.
                let read = unsafe {
                    libc::read(libc::STDIN_FILENO, buffer.as_mut_ptr().cast(), buffer.len())
                };
                if read > 0 {
                    if sender
                        .send(ReaderMessage::Data(buffer[..read as usize].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                    // Always after the send, never before: the pump must never
                    // wake to an empty channel and go back to sleep with the
                    // bytes still in flight.
                    wake();
                    continue;
                }
                if read < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                let _ = sender.send(ReaderMessage::Ended);
                wake();
                return;
            }
        });
        Self {
            input: receiver,
            ready,
            ended: false,
        }
    }
}

impl ProxyStdio for ProcessStdio {
    fn take_input(&mut self) -> InputPoll {
        if self.ended {
            return InputPoll::None;
        }
        if let Some(fd) = self.ready_fd() {
            crate::terminal::clear_one_signal(fd);
        }
        match self.input.try_recv() {
            Ok(ReaderMessage::Data(data)) => InputPoll::Data(data),
            Ok(ReaderMessage::Ended) => {
                self.ended = true;
                InputPoll::Ended
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => InputPoll::None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.ended = true;
                InputPoll::Ended
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    }

    fn ready_fd(&self) -> Option<RawFd> {
        self.ready.as_ref().map(AsRawFd::as_raw_fd)
    }
}

/// Diagnostics go to stderr. stdout belongs to the SSH transport.
pub fn diagnose(line: &str) {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "{line}");
}

// -- the pump --------------------------------------------------------------

/// Where this client records the host keys the bridge hands it.
pub struct KnownHostsTarget<'a> {
    pub path: &'a Path,
    /// `svartal-<name>`: the host `ssh` is looking the key up under.
    pub alias: &'a str,
}

pub struct ProxyInput<'a> {
    /// What a failure calls this workspace.
    pub label: &'a str,
    /// One OpenSSH public key line; the workspace's whole authorized-keys file.
    pub public_key: &'a str,
    pub client_name: Option<&'a str>,
    pub known_hosts: KnownHostsTarget<'a>,
    /// Overridden in tests. Doc §4.2 fixes it at five seconds.
    pub ping_interval: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshOutcome {
    /// The `EXIT` reason, or how the connection ended without one.
    pub reason: String,
    /// What this process exits with.
    pub exit_code: i32,
    pub connection_id: Option<String>,
}

/// Copy bytes until the connection ends.
///
/// One loop owns the socket, exactly as the shell's pump does: it reads what
/// the workspace sent, writes what arrived on stdin, and keeps the five-second
/// ping going. Nothing is sent between `OPEN` and `READY` — the server has no
/// sshd to write to yet, and the host key has to be recorded before the key
/// exchange starts.
pub fn run_ssh_proxy<T: BinaryTransport>(
    transport: &mut T,
    stdio: &mut dyn ProxyStdio,
    input: &ProxyInput<'_>,
) -> Result<SshOutcome, SshError> {
    let label = input.label;
    let mut decoder = FrameDecoder::new();
    let mut ready: Option<Ready> = None;
    let mut stdin_ended = false;
    let mut last_ping = Instant::now();

    // Doc §3.3: `OPEN` is the first frame, always.
    transport
        .send(&encode_open_frame(input.public_key, input.client_name))
        .map_err(|error| connect_error(label, error))?;

    let waitable = transport.readable_fd().zip(stdio.ready_fd());
    loop {
        if ready.is_some() && last_ping.elapsed() >= input.ping_interval {
            last_ping = Instant::now();
            if let Err(error) = transport.send(&encode_frame(FRAME_PING, &[])) {
                return Ok(ended_by(&error, ready.as_ref()));
            }
        }

        let socket_wait = match waitable {
            None => PUMP_TICK,
            Some((socket, local)) => {
                if wait_for_activity(socket, local, PUMP_TICK) {
                    PUMP_TICK
                } else {
                    IDLE_TICK
                }
            }
        };

        let message = match transport.recv(socket_wait) {
            Ok(message) => message,
            // Doc §3.5: a connection that dies before `EXIT` carries no frame at
            // all, and a closed socket is an ended connection.
            Err(error) => return Ok(ended_by(&error, ready.as_ref())),
        };
        if let Some(bytes) = message {
            let frames = decoder
                .push(&bytes)
                .map_err(|detail| protocol_error(label, detail))?;
            for frame in frames {
                match frame.kind {
                    FRAME_READY => {
                        if ready.is_some() {
                            return Err(protocol_error(label, "a second READY frame"));
                        }
                        let decoded = decode_ready(&frame.payload)
                            .map_err(|detail| protocol_error(label, detail))?;
                        // Doc §8.3: before a single byte is pumped.
                        write_known_host(
                            input.known_hosts.path,
                            input.known_hosts.alias,
                            &decoded.host_public_key,
                        )
                        .map_err(|detail| SshError::KnownHosts {
                            path: input.known_hosts.path.display().to_string(),
                            detail,
                        })?;
                        ready = Some(decoded);
                    }
                    FRAME_STDOUT => {
                        if ready.is_none() {
                            return Err(protocol_error(label, "a STDOUT frame before READY"));
                        }
                        if !frame.payload.is_empty() {
                            stdio.write(&frame.payload);
                        }
                    }
                    FRAME_EXIT => {
                        let decoded = decode_exit(&frame.payload).unwrap_or_else(|detail| {
                            // A malformed `EXIT` still ends the connection; it
                            // just cannot say how.
                            diagnose(&format!("sv: {detail}"));
                            ExitFrame {
                                reason: "protocol_error".to_string(),
                                exit_code: None,
                            }
                        });
                        return Ok(SshOutcome {
                            exit_code: exit_status_for(&decoded.reason, decoded.exit_code),
                            reason: decoded.reason,
                            connection_id: ready.map(|value| value.connection_id),
                        });
                    }
                    // The framing is intact and the reader decides: `PONG`, and
                    // any type this version does not know, are not a reason to
                    // break a live SSH transport.
                    _ => {}
                }
            }
        }

        if ready.is_none() || stdin_ended {
            continue;
        }
        match stdio.take_input() {
            InputPoll::None => {}
            InputPoll::Data(data) => {
                for frame in encode_stdin_frames(&data) {
                    if let Err(error) = transport.send(&frame) {
                        return Ok(ended_by(&error, ready.as_ref()));
                    }
                }
            }
            // Doc §8.4: stdin EOF is a half-close. The connection keeps running
            // and this client keeps reading until `EXIT` or close.
            InputPoll::Ended => {
                stdin_ended = true;
                if let Err(error) = transport.send(&encode_frame(FRAME_STDIN_EOF, &[])) {
                    return Ok(ended_by(&error, ready.as_ref()));
                }
            }
        }
    }
}

/// A socket that ended without an `EXIT` frame. Non-zero, always: `ssh` has
/// nothing else to read the failure from.
fn ended_by(error: &TransportError, ready: Option<&Ready>) -> SshOutcome {
    SshOutcome {
        reason: match error {
            TransportError::Closed(_) => "closed".to_string(),
            TransportError::Failed(_) => "client_gone".to_string(),
        },
        exit_code: GENERIC_EXIT_CODE,
        connection_id: ready.map(|value| value.connection_id.clone()),
    }
}

// -- the connect chain -----------------------------------------------------

pub struct BridgeConnectInput<'a> {
    pub relay_url: &'a str,
    pub client_id: &'a str,
    /// The OIDC access token from the local Svartal credential.
    pub access_token: &'a str,
    pub target: &'a ShellTarget,
    pub dpop_key: &'a DpopKey,
    pub client_metadata: ClientMetadata,
}

/// Relay exchange, relay connect, workspace token, WebSocket ticket — and then
/// a URL on `/ssh`.
///
/// The shape is `shell::connect_workspace`'s, and deliberately not a call to
/// it: the scope set is `terminal:operate` alone (doc §2 — nothing on this path
/// looks a working directory up), the route is `/ssh`, and every failure has to
/// read as an ssh connection failing rather than a shell failing to open.
pub fn connect_bridge(
    http: &dyn HttpTransport,
    input: &BridgeConnectInput<'_>,
) -> Result<String, SshError> {
    let label = input.target.label.as_str();
    let proof = |url: &str, access_token: Option<&str>| -> Result<String, SshError> {
        let jti = random_uuid_v4().map_err(|error| connect_error(label, error))?;
        input
            .dpop_key
            .create_proof(&ProofRequest::now("POST", url, access_token, &jti))
            .map_err(|error| connect_error(label, error))
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
    .map_err(|error| connect_error(label, error))?;

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
    .map_err(|error| connect_error(label, error))?;

    let http_base_url = connection.endpoint.http_base_url.clone();
    let ws_base_url = if connection.endpoint.ws_base_url.trim().is_empty() {
        workspace::default_ws_base_url(&http_base_url)
            .map_err(|error| connect_error(label, error))?
    } else {
        connection.endpoint.ws_base_url.clone()
    };

    let token_url =
        workspace::token_url(&http_base_url).map_err(|error| connect_error(label, error))?;
    let workspace_token = workspace::exchange_access_token(
        http,
        &WorkspaceTokenExchange {
            http_base_url: &http_base_url,
            label,
            credential: &connection.credential,
            scopes: &SSH_SCOPES,
            dpop_proof: &proof(&token_url, None)?,
            client_metadata: input.client_metadata,
        },
    )
    .map_err(|error| match error {
        // The grant's own refusal keeps its own sentence.
        workspace::WorkspaceError::TerminalNotAllowed { label } => {
            SshError::TerminalNotAllowed { label }
        }
        other => connect_error(label, other),
    })?;

    let ticket_url = workspace::websocket_ticket_url(&http_base_url)
        .map_err(|error| connect_error(label, error))?;
    let ticket = workspace::issue_websocket_ticket(
        http,
        &http_base_url,
        label,
        &workspace_token.access_token,
        // Bound to the access token this request carries: the workspace
        // verifies the proof's `ath` against it.
        &proof(&ticket_url, Some(&workspace_token.access_token))?,
    )
    .map_err(|error| connect_error(label, error))?;

    workspace::websocket_url_at(&ws_base_url, SSH_ROUTE_PATH, &ticket.ticket)
        .map_err(|error| connect_error(label, error))
}

// -- the local ssh files ---------------------------------------------------

/// The directory inside the CLI's state directory that holds the ssh files.
pub const SSH_DIRECTORY_NAME: &str = "ssh";
/// The client key file name. `ssh-keygen`'s own default for an ed25519 key.
pub const CLIENT_KEY_FILE_NAME: &str = "id_ed25519";
/// The workspace host keys this CLI has been told about, over the bridge.
pub const KNOWN_HOSTS_FILE_NAME: &str = "known_hosts";
/// Every alias this CLI writes is `svartal-` plus the name that was typed.
pub const HOST_ALIAS_PREFIX: &str = "svartal-";
/// The account an SSH session lands on inside the workspace container.
pub const SSH_USER: &str = "svartal";

/// How long to wait for another process's `known_hosts` lock, and when to treat
/// one as abandoned. A `ProxyCommand` holds it for a single small rewrite, so a
/// lock that is seconds old is a crashed process, not a busy one.
const LOCK_WAIT: Duration = Duration::from_secs(5);
const LOCK_STALE: Duration = Duration::from_secs(10);
const LOCK_RETRY: Duration = Duration::from_millis(20);

pub fn ssh_directory(state_directory: &Path) -> PathBuf {
    state_directory.join(SSH_DIRECTORY_NAME)
}

pub fn client_key_path(state_directory: &Path) -> PathBuf {
    ssh_directory(state_directory).join(CLIENT_KEY_FILE_NAME)
}

pub fn client_public_key_path(state_directory: &Path) -> PathBuf {
    ssh_directory(state_directory).join(format!("{CLIENT_KEY_FILE_NAME}.pub"))
}

pub fn known_hosts_path(state_directory: &Path) -> PathBuf {
    ssh_directory(state_directory).join(KNOWN_HOSTS_FILE_NAME)
}

/// The `<name>` half of an alias: lowercase, `[a-z0-9._-]`, never empty.
pub fn alias_token(name: &str) -> String {
    let mut token = String::with_capacity(name.len());
    let mut pending_separator = false;
    for character in name.trim().to_lowercase().chars() {
        if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
            if pending_separator && !token.is_empty() {
                token.push('-');
            }
            pending_separator = false;
            token.push(character);
        } else {
            pending_separator = true;
        }
    }
    let token = token.trim_matches('-').to_string();
    if token.is_empty() {
        "workspace".to_string()
    } else {
        token
    }
}

/// The host alias for a target, as `ssh` will see it.
///
/// `sv ssh-setup web` writes `Host svartal-web`, so `ssh svartal-web` reaches
/// that workspace and `known_hosts` is keyed by the same word.
pub fn host_alias(name: &str) -> String {
    format!("{HOST_ALIAS_PREFIX}{}", alias_token(name))
}

/// The default `~/.ssh/config`, from this process's environment.
pub fn default_ssh_config_path(environment: &Environment) -> Result<PathBuf, SshError> {
    let home = environment
        .get("HOME")
        .or_else(|| environment.get("USERPROFILE"))
        .map(|value| value.trim())
        .unwrap_or_default();
    if home.is_empty() {
        return Err(setup_error(
            "Cannot find a home directory to write ~/.ssh/config into. Set HOME, or run `sv ssh-setup --print` and paste the block yourself.",
        ));
    }
    Ok(PathBuf::from(home.trim_end_matches('/'))
        .join(".ssh")
        .join("config"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientKey {
    pub private_key_path: PathBuf,
    pub public_key_path: PathBuf,
    /// One OpenSSH public key line, exactly as `OPEN.publicKey` carries it.
    pub public_key: String,
    /// False when the key was already there, which is the ordinary case.
    pub created: bool,
}

/// The client key, minted on first use.
///
/// An existing private key is never regenerated — not when the public half is
/// missing either, which is what `ssh-keygen -y` is for. The same discipline
/// the DPoP key store follows, for the same reason: a new key is a silent
/// invalidation of everything bound to the old one.
pub fn ensure_client_key(state_directory: &Path) -> Result<ClientKey, SshError> {
    let directory = ssh_directory(state_directory);
    crate::fsutil::ensure_state_directory(&directory).map_err(setup_error)?;
    let private_key_path = client_key_path(state_directory);
    let public_key_path = client_public_key_path(state_directory);

    if private_key_path.exists() {
        let public_key = read_or_derive_public_key(&private_key_path, &public_key_path)?;
        return Ok(ClientKey {
            private_key_path,
            public_key_path,
            public_key,
            created: false,
        });
    }

    // The command from ssh-bridge.md §8.2, word for word.
    run_keygen(&["-t", "ed25519", "-N", "", "-f", &private_key_path.display().to_string()])
        .map_err(|detail| {
            setup_error(format!(
                "Could not create an ssh key in {}: {detail}. An ssh client machine has ssh-keygen; if this one does not, install OpenSSH and run `sv ssh-setup` again.",
                directory.display()
            ))
        })?;
    let public_key = read_or_derive_public_key(&private_key_path, &public_key_path)?;
    Ok(ClientKey {
        private_key_path,
        public_key_path,
        public_key,
        created: true,
    })
}

fn read_or_derive_public_key(
    private_key_path: &Path,
    public_key_path: &Path,
) -> Result<String, SshError> {
    if let Ok(contents) = std::fs::read_to_string(public_key_path) {
        let line = contents.trim();
        if !line.is_empty() {
            return Ok(line.to_string());
        }
    }
    // The private half exists and the public one does not: derive it rather
    // than mint a second key.
    let derived =
        run_keygen(&["-y", "-f", &private_key_path.display().to_string()]).map_err(|detail| {
            setup_error(format!(
                "Could not read the public half of {}: {detail}",
                private_key_path.display()
            ))
        })?;
    let line = derived.trim().to_string();
    if line.is_empty() {
        return Err(setup_error(format!(
            "{} has no readable public key.",
            private_key_path.display()
        )));
    }
    Ok(line)
}

fn run_keygen(args: &[&str]) -> Result<String, String> {
    let output = Command::new("ssh-keygen")
        .args(args)
        .output()
        .map_err(|error| format!("ssh-keygen could not be run: {error}"))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if detail.is_empty() {
            "ssh-keygen failed".to_string()
        } else {
            detail
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// What an edit did, so the caller can say it out loud (or say nothing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownHostsChange {
    Added,
    Replaced,
    Unchanged,
    Removed,
}

/// The host keys recorded in a `known_hosts` file, in file order.
pub fn read_known_hosts(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// True for a line this CLI wrote for that alias.
///
/// An entry may name several hosts, comma-separated. Ours name one; a
/// hand-written one may not, and dropping the whole line would take a host this
/// CLI never wrote away from the person who did.
fn is_entry_for(line: &str, alias: &str) -> bool {
    match line.split_whitespace().next() {
        Some(host) => !host.contains(',') && host == alias,
        None => false,
    }
}

/// Record a workspace's host key under its alias, replacing any older one.
///
/// Called from `ssh-proxy` on `READY`, before a single byte is pumped: the
/// `ProxyCommand` starts before key exchange does, so this is the last moment
/// the key can be pinned without a trust-on-first-use prompt.
pub fn write_known_host(
    path: &Path,
    alias: &str,
    host_public_key: &str,
) -> Result<KnownHostsChange, String> {
    let line = format!("{alias} {}", host_public_key.trim());
    with_known_hosts_lock(path, || {
        let existing = read_known_hosts(path);
        let mine: Vec<&String> = existing
            .iter()
            .filter(|entry| is_entry_for(entry, alias))
            .collect();
        if mine.len() == 1 && *mine[0] == line {
            return Ok(KnownHostsChange::Unchanged);
        }
        let mut lines: Vec<String> = existing
            .iter()
            .filter(|entry| !is_entry_for(entry, alias))
            .cloned()
            .collect();
        lines.push(line);
        write_lines(path, &lines)?;
        Ok(if mine.is_empty() {
            KnownHostsChange::Added
        } else {
            KnownHostsChange::Replaced
        })
    })
}

/// Forget every host key recorded for an alias. `sv ssh-setup --reset-hosts`.
pub fn remove_known_host(path: &Path, alias: &str) -> Result<KnownHostsChange, String> {
    with_known_hosts_lock(path, || {
        let existing = read_known_hosts(path);
        let lines: Vec<String> = existing
            .iter()
            .filter(|entry| !is_entry_for(entry, alias))
            .cloned()
            .collect();
        if lines.len() == existing.len() {
            return Ok(KnownHostsChange::Unchanged);
        }
        write_lines(path, &lines)?;
        Ok(KnownHostsChange::Removed)
    })
}

fn write_lines(path: &Path, lines: &[String]) -> Result<(), String> {
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    crate::fsutil::write_private_file(path, body.as_bytes()).map_err(|error| error.to_string())
}

/// Hold an exclusive lock over `known_hosts` for one read-modify-write.
///
/// An `O_EXCL` lock file, not `flock(2)`: the TypeScript `sv` and this one have
/// to exclude *each other*, Node has no portable `flock`, and this is the
/// mechanism both can implement the same way on every Unix. A lock older than
/// `LOCK_STALE` belonged to a process that died holding it and is taken over; a
/// lock that never frees is reported on stderr and the edit proceeds anyway,
/// because refusing it would cost the person the connection.
fn with_known_hosts_lock<A>(
    path: &Path,
    edit: impl FnOnce() -> Result<A, String>,
) -> Result<A, String> {
    if let Some(parent) = path.parent() {
        crate::fsutil::ensure_state_directory(parent).map_err(|error| error.to_string())?;
    }
    let lock_path = path.with_file_name(format!(
        "{}.lock",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(KNOWN_HOSTS_FILE_NAME)
    ));
    let held = acquire_lock(&lock_path)?;
    let outcome = edit();
    if held {
        // A lock taken over as stale is someone else's to remove now.
        let _ = std::fs::remove_file(&lock_path);
    }
    outcome
}

fn acquire_lock(lock_path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(crate::fsutil::PRIVATE_FILE_MODE)
            .open(lock_path)
        {
            Ok(_) => return Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("could not lock {}: {error}", lock_path.display())),
        }
        if is_stale_lock(lock_path) {
            let _ = std::fs::remove_file(lock_path);
            continue;
        }
        if Instant::now() >= deadline {
            diagnose(&format!(
                "sv: {} is locked by another process; writing the host key anyway.",
                lock_path.display()
            ));
            return Ok(false);
        }
        std::thread::sleep(LOCK_RETRY);
    }
}

fn is_stale_lock(lock_path: &Path) -> bool {
    std::fs::metadata(lock_path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| SystemTime::now().duration_since(modified).ok())
        .is_some_and(|age| age > LOCK_STALE)
}

/// The first line of the block this CLI owns, and the last.
pub fn block_markers(alias: &str) -> (String, String) {
    (
        format!("# >>> sv ssh-setup {alias} >>>"),
        format!("# <<< sv ssh-setup {alias} <<<"),
    )
}

pub struct ConfigBlockInput<'a> {
    /// `svartal-<name>`, the host a person types after `ssh`.
    pub alias: &'a str,
    /// What `ssh-proxy` is given: the same word the alias was built from.
    pub target: &'a str,
    /// The `sv` this command was invoked as.
    pub binary: &'a str,
    pub identity_file: &'a str,
    pub known_hosts_file: &'a str,
}

/// The `~/.ssh/config` block, exactly as `ssh-bridge.md` §8 prints it.
///
/// The paths are the resolved ones rather than the document's `~/…`: the state
/// directory moves with `SVARTAL_CONFIG_DIR` and `XDG_CONFIG_HOME`, and an
/// `IdentityFile` that points at the wrong one is a refusal nobody can read.
pub fn ssh_config_block(input: &ConfigBlockInput<'_>) -> String {
    let (start, end) = block_markers(input.alias);
    [
        start,
        format!("Host {}", input.alias),
        format!("  User {SSH_USER}"),
        format!(
            "  ProxyCommand {} ssh-proxy {}",
            quote_argument(input.binary),
            input.target
        ),
        format!("  IdentityFile {}", quote_argument(input.identity_file)),
        "  IdentitiesOnly yes".to_string(),
        format!(
            "  UserKnownHostsFile {}",
            quote_argument(input.known_hosts_file)
        ),
        "  StrictHostKeyChecking accept-new".to_string(),
        "  ForwardAgent no".to_string(),
        end,
    ]
    .join("\n")
}

/// ssh's config parser reads a quoted argument as one token.
fn quote_argument(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value.to_string()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigChange {
    Created,
    Added,
    Replaced,
    Unchanged,
}

/// Put the block in `~/.ssh/config`, replacing the one with the same marker.
///
/// A file that is not there is created `0600` in a `0700` `~/.ssh`, which is
/// what OpenSSH insists on anyway. Nothing outside the markers is read for
/// meaning or rewritten.
pub fn apply_ssh_config_block(
    path: &Path,
    alias: &str,
    block: &str,
) -> Result<ConfigChange, SshError> {
    let (start, end) = block_markers(alias);
    let existing = match std::fs::read_to_string(path) {
        Ok(contents) => Some(contents),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(setup_error(format!(
                "could not read {}: {error}",
                path.display()
            )));
        }
    };

    let Some(existing) = existing else {
        crate::fsutil::write_private_file(path, format!("{block}\n").as_bytes())
            .map_err(|error| setup_error(format!("could not write {}: {error}", path.display())))?;
        return Ok(ConfigChange::Created);
    };

    if let (Some(from), Some(to)) = (existing.find(&start), existing.find(&end))
        && to > from
    {
        let replaced = format!(
            "{}{block}{}",
            &existing[..from],
            &existing[to + end.len()..]
        );
        if replaced == existing {
            return Ok(ConfigChange::Unchanged);
        }
        crate::fsutil::write_private_file(path, replaced.as_bytes())
            .map_err(|error| setup_error(format!("could not write {}: {error}", path.display())))?;
        return Ok(ConfigChange::Replaced);
    }

    let separator = if existing.is_empty() || existing.ends_with("\n\n") {
        ""
    } else if existing.ends_with('\n') {
        "\n"
    } else {
        "\n\n"
    };
    crate::fsutil::write_private_file(path, format!("{existing}{separator}{block}\n").as_bytes())
        .map_err(|error| setup_error(format!("could not write {}: {error}", path.display())))?;
    Ok(ConfigChange::Added)
}

pub struct SetupInput<'a> {
    pub state_directory: &'a Path,
    /// The word `ssh-proxy` will be given, and the alias is built from.
    pub target: &'a str,
    /// The `sv` this command was invoked as, for the `ProxyCommand` line.
    pub binary: &'a str,
    pub ssh_config_path: &'a Path,
    /// Print the block instead of writing it.
    pub print: bool,
    /// Forget the host keys recorded for this alias first.
    pub reset_hosts: bool,
}

#[derive(Debug, Clone)]
pub struct SetupOutcome {
    pub alias: String,
    pub block: String,
    pub key: ClientKey,
    /// `None` when `--print` was asked for: nothing was written.
    pub config: Option<ConfigChange>,
    pub hosts: Option<KnownHostsChange>,
    pub ssh_config_path: PathBuf,
}

/// `sv ssh-setup <target>`: mint the key if it is missing, then write the block.
///
/// Applying is the default. `--print` is the opt-out for a person who keeps
/// their ssh config under version control, and it is the only mode that touches
/// nothing.
pub fn run_ssh_setup(input: &SetupInput<'_>) -> Result<SetupOutcome, SshError> {
    let alias = host_alias(input.target);
    let key = ensure_client_key(input.state_directory)?;
    let hosts_path = known_hosts_path(input.state_directory);
    let block = ssh_config_block(&ConfigBlockInput {
        alias: &alias,
        target: &alias_token(input.target),
        binary: input.binary,
        identity_file: &key.private_key_path.display().to_string(),
        known_hosts_file: &hosts_path.display().to_string(),
    });

    let hosts = if input.reset_hosts {
        Some(
            remove_known_host(&hosts_path, &alias).map_err(|detail| SshError::KnownHosts {
                path: hosts_path.display().to_string(),
                detail,
            })?,
        )
    } else {
        None
    };

    if input.print {
        return Ok(SetupOutcome {
            alias,
            block,
            key,
            config: None,
            hosts,
            ssh_config_path: input.ssh_config_path.to_path_buf(),
        });
    }

    let config = apply_ssh_config_block(input.ssh_config_path, &alias, &block)?;
    Ok(SetupOutcome {
        alias,
        block,
        key,
        config: Some(config),
        hosts,
        ssh_config_path: input.ssh_config_path.to_path_buf(),
    })
}

/// The lines `sv ssh-setup` prints, for each of the things it did.
pub fn describe_ssh_setup(outcome: &SetupOutcome) -> Vec<String> {
    let mut lines = Vec::new();
    if outcome.key.created {
        lines.push(format!(
            "Made an ssh key for this machine: {}.",
            outcome.key.private_key_path.display()
        ));
    }
    if outcome.hosts == Some(KnownHostsChange::Removed) {
        lines.push(format!(
            "Forgot the host key recorded for {}.",
            outcome.alias
        ));
    }
    let path = outcome.ssh_config_path.display();
    let alias = &outcome.alias;
    match outcome.config {
        Some(ConfigChange::Created) => {
            lines.push(format!("Wrote {path}. Connect with `ssh {alias}`."));
        }
        Some(ConfigChange::Added) => {
            lines.push(format!(
                "Added {alias} to {path}. Connect with `ssh {alias}`."
            ));
        }
        Some(ConfigChange::Replaced) => {
            lines.push(format!(
                "Updated {alias} in {path}. Connect with `ssh {alias}`."
            ));
        }
        Some(ConfigChange::Unchanged) => {
            lines.push(format!(
                "{alias} is already set up in {path}. Connect with `ssh {alias}`."
            ));
        }
        None => {}
    }
    lines
}

/// The `sv` to put in the `ProxyCommand`.
///
/// The path this binary was started as, so a `sv` that is not on `PATH` — a
/// checkout, a second version, a Homebrew Cellar path — still works when `ssh`
/// runs it with an environment of its own. `sv` is the fallback for the case
/// where the runtime cannot say.
pub fn invoked_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .map(|path| path.display().to_string())
        .filter(|path| !path.is_empty())
        .unwrap_or_else(|| "sv".to_string())
}
