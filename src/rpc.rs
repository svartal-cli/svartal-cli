//! The workspace RPC protocol, as it goes over the WebSocket.
//!
//! This is Effect's RPC wire format (`effect/unstable/rpc`, beta.103) with the
//! JSON serialization (`RpcSerialization.layerJson`) and the socket protocol
//! (`RpcClient.makeProtocolSocket`). Nothing about it is Svartal-specific, and
//! nothing about it was written down anywhere, so it is written down here.
//!
//! **Framing.** One JSON value per WebSocket text frame. The client always
//! sends a single object; the server may send a single object or an array of
//! them, and an array is treated as a batch in order.
//!
//! **Client to server.**
//!
//! ```json
//! {"_tag":"Request","id":"0","tag":"terminal.open","payload":{…},"headers":[]}
//! {"_tag":"Ack","requestId":"0"}
//! {"_tag":"Interrupt","requestId":"0"}
//! {"_tag":"Ping"}
//! ```
//!
//! `id` is a per-connection counter, **encoded as a string** — Effect's numeric
//! default cannot correlate a response from an older server, so Ivaldi's
//! `protocol.ts` pins string ids and this client does the same. `headers` is an
//! array of `[name, value]` pairs and is empty here.
//!
//! **Server to client.**
//!
//! ```json
//! {"_tag":"Chunk","requestId":"0","values":[…]}
//! {"_tag":"Exit","requestId":"0","exit":{"_tag":"Success","value":…}}
//! {"_tag":"Exit","requestId":"0","exit":{"_tag":"Failure","cause":[{"_tag":"Fail","error":{…}}]}}
//! {"_tag":"Pong"}
//! {"_tag":"Defect","defect":…}
//! ```
//!
//! **Acks are mandatory for streams.** The socket protocol sets
//! `supportsAck: true`, so every `Chunk` must be answered with an `Ack` for the
//! same `requestId` or the server stops sending after its window fills. This is
//! the one rule that is invisible until a terminal goes quiet mid-session.
//!
//! **Ping.** The reference client sends `Ping` every five seconds and treats a
//! missing `Pong` before the next one as a dead connection.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

/// `Effect.delay("5 seconds")` in `makePinger`.
pub const PING_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum RpcError {
    /// The socket failed, or was closed under us.
    Transport(String),
    /// The call did not finish in time.
    Timeout,
    /// The RPC's own declared error. Carries the encoded error value, whose
    /// `_tag` names it.
    Failed(Value),
    /// A defect: the workspace threw where it declared it could not.
    Defect(Value),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(detail) => write!(f, "{detail}"),
            Self::Timeout => write!(f, "the workspace did not answer in time."),
            Self::Failed(error) => write!(f, "{}", describe_error(error)),
            Self::Defect(defect) => write!(f, "{}", describe_error(defect)),
        }
    }
}

impl std::error::Error for RpcError {}

impl RpcError {
    /// The `_tag` of a declared error, which is how the CLI tells a
    /// namespace refusal from any other failure.
    pub fn tag(&self) -> Option<&str> {
        match self {
            Self::Failed(error) | Self::Defect(error) => {
                error.get("_tag").and_then(Value::as_str)
            }
            _ => None,
        }
    }
}

/// `messageOf` in the TypeScript CLI: the error's own sentence when it has one.
pub fn describe_error(error: &Value) -> String {
    if let Some(message) = error.get("message").and_then(Value::as_str)
        && !message.trim().is_empty()
    {
        return message.to_string();
    }
    if let Some(tag) = error.get("_tag").and_then(Value::as_str) {
        return tag.to_string();
    }
    if let Some(text) = error.as_str()
        && !text.trim().is_empty()
    {
        return text.to_string();
    }
    "the workspace refused the connection.".to_string()
}

#[derive(Debug)]
pub enum TransportError {
    Closed(String),
    Failed(String),
    /// The far end broke the wire contract itself — a text message on a socket
    /// the protocol says is binary only. Not a connection that ended: a caller
    /// reports this as a protocol error rather than as a hang-up, because the
    /// two mean different things to whoever reads the message.
    Protocol(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed(detail) | Self::Failed(detail) | Self::Protocol(detail) => {
                write!(f, "{detail}")
            }
        }
    }
}

/// One text-frame transport. `recv` returns `Ok(None)` when the wait elapsed
/// with no frame, which is what lets one thread own the socket and still do
/// other work.
pub trait RpcTransport {
    fn recv(&mut self, timeout: Duration) -> Result<Option<String>, TransportError>;
    fn send(&mut self, text: &str) -> Result<(), TransportError>;

    /// The descriptor that becomes readable when the workspace sends something.
    ///
    /// A caller that has one can wait on it alongside its own descriptors and
    /// stop polling. `None` — the test transports — keeps the timeout-driven
    /// behaviour, so nothing about the protocol depends on this.
    fn readable_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }

    /// Hang up politely when the caller is done. A test transport has nothing
    /// to hang up, so the default does nothing.
    fn shutdown(&mut self) {}
}

/// A decoded server message.
#[derive(Debug, Clone)]
pub enum Incoming {
    Chunk { request_id: String, values: Vec<Value> },
    Exit { request_id: String, exit: Exit },
    Pong,
    Defect(Value),
    /// A message this client does not model. Ignored, deliberately: the
    /// protocol grows server-side and an unknown tag is not a failure.
    Other,
}

#[derive(Debug, Clone)]
pub enum Exit {
    Success(Value),
    Failure(Value),
}

pub struct RpcClient<T: RpcTransport> {
    transport: T,
    next_id: u64,
    buffered: VecDeque<Incoming>,
    last_ping_at: Option<Instant>,
    awaiting_pong: bool,
}

impl<T: RpcTransport> RpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: 0,
            buffered: VecDeque::new(),
            // The reference pinger waits a full interval before its first
            // ping, so a short-lived connection sends none at all.
            last_ping_at: Some(Instant::now()),
            awaiting_pong: false,
        }
    }

    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// See `RpcTransport::readable_fd`.
    pub fn readable_fd(&self) -> Option<std::os::fd::RawFd> {
        self.transport.readable_fd()
    }

    /// Send a request and return the id its responses will carry.
    pub fn request(&mut self, tag: &str, payload: Value) -> Result<String, RpcError> {
        let id = self.next_id.to_string();
        self.next_id += 1;
        let message = json!({
            "_tag": "Request",
            "id": id,
            "tag": tag,
            "payload": payload,
            "headers": [],
        });
        self.send(&message)?;
        Ok(id)
    }

    pub fn ack(&mut self, request_id: &str) -> Result<(), RpcError> {
        self.send(&json!({ "_tag": "Ack", "requestId": request_id }))
    }

    pub fn interrupt(&mut self, request_id: &str) -> Result<(), RpcError> {
        self.send(&json!({ "_tag": "Interrupt", "requestId": request_id }))
    }

    /// Send a `Ping` if one is due. A pong that never arrives before the next
    /// ping is a dead connection, which is how the reference client decides.
    pub fn ping_if_due(&mut self) -> Result<(), RpcError> {
        let due = self.last_ping_at.is_none_or(|last| last.elapsed() >= PING_INTERVAL);
        if !due {
            return Ok(());
        }
        if self.awaiting_pong {
            return Err(RpcError::Transport(
                "the workspace stopped answering; the connection is gone.".to_string(),
            ));
        }
        self.last_ping_at = Some(Instant::now());
        self.awaiting_pong = true;
        self.send(&json!({ "_tag": "Ping" }))
    }

    fn send(&mut self, message: &Value) -> Result<(), RpcError> {
        let text = serde_json::to_string(message)
            .map_err(|error| RpcError::Transport(format!("could not encode a request: {error}")))?;
        self.transport.send(&text).map_err(|error| RpcError::Transport(error.to_string()))
    }

    /// Read at most one frame, decode it, and answer whatever the protocol
    /// requires (an `Ack` per chunk). Returns everything the frame carried.
    pub fn pump(&mut self, timeout: Duration) -> Result<Vec<Incoming>, RpcError> {
        if let Some(buffered) = self.buffered.pop_front() {
            return Ok(vec![buffered]);
        }
        let Some(text) =
            self.transport.recv(timeout).map_err(|error| RpcError::Transport(error.to_string()))?
        else {
            return Ok(Vec::new());
        };
        let decoded: Value = serde_json::from_str(&text).map_err(|error| {
            RpcError::Transport(format!("the workspace sent something that is not JSON: {error}"))
        })?;
        let frames = match decoded {
            Value::Array(values) => values,
            other => vec![other],
        };
        let mut received = Vec::with_capacity(frames.len());
        for frame in &frames {
            let message = decode_incoming(frame);
            match &message {
                Incoming::Chunk { request_id, .. } => {
                    let request_id = request_id.clone();
                    self.ack(&request_id)?;
                }
                Incoming::Pong => {
                    self.awaiting_pong = false;
                }
                _ => {}
            }
            received.push(message);
        }
        Ok(received)
    }

    /// Send a request and wait for its `Exit`. Anything that arrives meanwhile
    /// is buffered for the caller's own loop rather than dropped.
    pub fn call(&mut self, tag: &str, payload: Value, timeout: Duration) -> Result<Value, RpcError> {
        let id = self.request(tag, payload)?;
        let deadline = Instant::now() + timeout;
        let mut other = Vec::new();
        loop {
            if Instant::now() >= deadline {
                self.buffered.extend(other);
                return Err(RpcError::Timeout);
            }
            for message in self.pump(Duration::from_millis(100))? {
                match message {
                    Incoming::Exit { ref request_id, ref exit } if *request_id == id => {
                        self.buffered.extend(other);
                        return match exit {
                            Exit::Success(value) => Ok(value.clone()),
                            Exit::Failure(error) => Err(failure_of(error)),
                        };
                    }
                    Incoming::Defect(defect) => {
                        self.buffered.extend(other);
                        return Err(RpcError::Defect(defect));
                    }
                    Incoming::Pong | Incoming::Other => {}
                    keep => other.push(keep),
                }
            }
        }
    }
}

/// A `Failure` cause is a list; the first `Fail` is the declared error and the
/// first `Die` is a defect. Anything else is an interrupt, which for a client
/// means the workspace gave up on the call.
fn failure_of(cause: &Value) -> RpcError {
    let entries = cause.as_array().map(Vec::as_slice).unwrap_or_default();
    for entry in entries {
        match entry.get("_tag").and_then(Value::as_str) {
            Some("Fail") => {
                return RpcError::Failed(entry.get("error").cloned().unwrap_or(Value::Null));
            }
            Some("Die") => {
                return RpcError::Defect(entry.get("defect").cloned().unwrap_or(Value::Null));
            }
            _ => {}
        }
    }
    RpcError::Transport("the workspace interrupted the call.".to_string())
}

fn decode_incoming(frame: &Value) -> Incoming {
    let tag = frame.get("_tag").and_then(Value::as_str).unwrap_or_default();
    match tag {
        "Chunk" => {
            let Some(request_id) = request_id_of(frame) else { return Incoming::Other };
            Incoming::Chunk {
                request_id,
                values: frame
                    .get("values")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default(),
            }
        }
        "Exit" => {
            let Some(request_id) = request_id_of(frame) else { return Incoming::Other };
            let exit = frame.get("exit").cloned().unwrap_or(Value::Null);
            let decoded = match exit.get("_tag").and_then(Value::as_str) {
                Some("Success") => Exit::Success(exit.get("value").cloned().unwrap_or(Value::Null)),
                _ => Exit::Failure(exit.get("cause").cloned().unwrap_or(Value::Null)),
            };
            Incoming::Exit { request_id, exit: decoded }
        }
        "Pong" => Incoming::Pong,
        "Defect" => Incoming::Defect(frame.get("defect").cloned().unwrap_or(Value::Null)),
        _ => Incoming::Other,
    }
}

/// Request ids are strings on this wire, but a server that answered with a
/// number still means the same request.
fn request_id_of(frame: &Value) -> Option<String> {
    match frame.get("requestId") {
        Some(Value::String(id)) => Some(id.clone()),
        Some(Value::Number(id)) => Some(id.to_string()),
        _ => None,
    }
}
