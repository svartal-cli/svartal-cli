//! The WebSocket the RPC protocol runs over.
//!
//! One thread owns the socket. Reads are given a short timeout instead of
//! blocking forever, so the same loop that waits for workspace output can also
//! send what was typed, resize on `SIGWINCH`, and keep the five-second ping
//! going — without a second thread touching the socket and without an async
//! runtime.
//!
//! TLS is rustls, the same implementation and root store `ureq` already links
//! for the HTTP calls, so this binary has one TLS stack rather than two.

use std::net::TcpStream;
use std::os::fd::{AsRawFd, RawFd};
use std::time::Duration;

use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Message, WebSocket};

use crate::rpc::{RpcTransport, TransportError};

/// `SOCKET_OPEN_TIMEOUT` in the reference session factory.
pub const OPEN_TIMEOUT: Duration = Duration::from_secs(15);

pub struct WebSocketTransport {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
}

impl WebSocketTransport {
    pub fn connect(url: &str) -> Result<Self, TransportError> {
        let (socket, _response) = tungstenite::connect(url)
            .map_err(|error| TransportError::Failed(describe(&error)))?;
        let transport = Self { socket };
        transport.set_timeouts(OPEN_TIMEOUT)?;
        transport.disable_nagle();
        Ok(transport)
    }

    /// Turn Nagle's algorithm off.
    ///
    /// Everything this socket carries is a keystroke or a screen update: small,
    /// and wanted now. Nagle holds a small write back until the previous one is
    /// acknowledged, which on a link with real latency turns one keystroke into
    /// a wait for a whole round trip that has nothing to do with it. That is the
    /// wrong trade for a terminal, and it is the same reason every ssh client
    /// sets this.
    ///
    /// A socket that refuses the option still works — it is a latency
    /// improvement, not a requirement — so a failure here is not worth failing
    /// a shell over.
    fn disable_nagle(&self) {
        if let Some(stream) = self.tcp_stream() {
            let _ = stream.set_nodelay(true);
        }
    }

    /// True when the kernel has this socket's Nagle off. Only the tests read it.
    pub fn is_nodelay(&self) -> bool {
        self.tcp_stream().is_some_and(|stream| stream.nodelay().unwrap_or(false))
    }

    fn tcp_stream(&self) -> Option<&TcpStream> {
        match self.socket.get_ref() {
            MaybeTlsStream::Plain(stream) => Some(stream),
            MaybeTlsStream::Rustls(stream) => Some(&stream.sock),
            _ => None,
        }
    }

    fn set_timeouts(&self, read: Duration) -> Result<(), TransportError> {
        let Some(stream) = self.tcp_stream() else {
            return Ok(());
        };
        stream
            .set_read_timeout(Some(read))
            .and_then(|()| stream.set_write_timeout(Some(OPEN_TIMEOUT)))
            .map_err(|error| TransportError::Failed(format!("the socket refused a timeout: {error}")))
    }

    /// Close politely. A dropped socket detaches the shell rather than ending
    /// it, so this is only about leaving the workspace's side tidy.
    pub fn close(&mut self) {
        let _ = self.socket.close(None);
        let _ = self.socket.flush();
    }
}

impl RpcTransport for WebSocketTransport {
    fn readable_fd(&self) -> Option<RawFd> {
        self.tcp_stream().map(AsRawFd::as_raw_fd)
    }

    fn recv(&mut self, timeout: Duration) -> Result<Option<String>, TransportError> {
        self.set_timeouts(timeout)?;
        match self.socket.read() {
            Ok(Message::Text(text)) => Ok(Some(text.as_str().to_string())),
            Ok(Message::Binary(bytes)) => String::from_utf8(bytes.to_vec())
                .map(Some)
                .map_err(|_| TransportError::Failed("the workspace sent a frame that is not text.".to_string())),
            // Control frames are answered by the library; nothing to hand up.
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Frame(_)) => Ok(None),
            Ok(Message::Close(_)) => Err(TransportError::Closed(closed_message())),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) =>
            {
                // The wait elapsed. Any half-read frame stays in the library's
                // buffer and continues on the next call.
                Ok(None)
            }
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                Err(TransportError::Closed(closed_message()))
            }
            Err(error) => Err(TransportError::Failed(describe(&error))),
        }
    }

    fn send(&mut self, text: &str) -> Result<(), TransportError> {
        match self.socket.send(Message::Text(text.into())) {
            Ok(()) => Ok(()),
            Err(tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed) => {
                Err(TransportError::Closed(closed_message()))
            }
            Err(error) => Err(TransportError::Failed(describe(&error))),
        }
    }
}

fn closed_message() -> String {
    "the connection to the workspace closed.".to_string()
}

fn describe(error: &tungstenite::Error) -> String {
    match error {
        tungstenite::Error::Http(response) => {
            format!("the workspace refused the WebSocket with HTTP {}.", response.status())
        }
        other => format!("{other}"),
    }
}
