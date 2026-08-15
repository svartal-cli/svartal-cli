//! The loopback HTTP server that catches the authorization response.
//!
//! Port of `src/loopback.ts`. It binds `127.0.0.1` and nothing else: binding a
//! routable interface would put an authorization code on the network, and the
//! code alone is enough to complete a sign-in.
//!
//! The parser is deliberately tiny. This server answers exactly one kind of
//! request — a browser redirect, `GET`, no body — and everything it does with
//! what it reads is hand the full URL to `OidcClient::complete_authorization`,
//! which is the only thing that validates it (`ID-13`).

use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use crate::config::LoopbackRedirect;

/// `ID-13` gives the transaction ten minutes; waiting longer than that would
/// only produce a callback the client has to reject anyway.
pub const CALLBACK_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// A browser sends a request line and a handful of headers. Anything past this
/// is not the callback.
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const POLL_INTERVAL: Duration = Duration::from_millis(50);

#[derive(Debug)]
pub enum LoopbackError {
    PortInUse { port: u16 },
    Listen { port: u16, cause: std::io::Error },
    Timeout,
}

impl std::fmt::Display for LoopbackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortInUse { port } => write!(
                f,
                "Port {port} is already in use, so the sign-in callback cannot be received there."
            ),
            Self::Listen { port, cause } => write!(
                f,
                "Could not listen on 127.0.0.1:{port} for the sign-in callback: {cause}"
            ),
            Self::Timeout => write!(f, "Timed out waiting for the Svartal sign-in callback."),
        }
    }
}

impl std::error::Error for LoopbackError {}

// The page is served at the callback URL itself, so without the replaceState
// the one-time authorization code and state stay visible in the address bar
// and in browser history. The code is spent and PKCE-bound by then, but a
// parameter-soup URL reads like something went wrong. `/auth/done` is never
// served; it exists only as the clean address the page renames itself to.
const COMPLETION_PAGE: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Svartal sign-in</title>
  </head>
  <body style="font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 32rem;">
    <p>Sign-in received. You can close this tab and return to your terminal.</p>
    <script>
      history.replaceState(null, "", "/auth/done");
    </script>
  </body>
</html>
"#;

const REJECTION_PAGE: &str = r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Svartal sign-in</title>
  </head>
  <body style="font-family: system-ui, sans-serif; margin: 4rem auto; max-width: 32rem;">
    <p>This is not the callback the terminal is waiting for.</p>
  </body>
</html>
"#;

#[derive(Debug)]
pub struct LoopbackServer {
    listener: TcpListener,
    host: String,
    port: u16,
    pathname: String,
}

impl LoopbackServer {
    /// Bind one of the registered callbacks. `PortInUse` is the signal to try
    /// the next one, so a second `sv login` can still sign in while the
    /// first port is held.
    pub fn bind(redirect: &LoopbackRedirect) -> Result<Self, LoopbackError> {
        Self::bind_to(&redirect.host, redirect.port, &redirect.pathname)
    }

    pub fn bind_to(host: &str, port: u16, pathname: &str) -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind((host, port)).map_err(|cause| {
            if cause.kind() == std::io::ErrorKind::AddrInUse {
                LoopbackError::PortInUse { port }
            } else {
                LoopbackError::Listen { port, cause }
            }
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|cause| LoopbackError::Listen { port, cause })?;
        let bound_port = listener.local_addr().map(|address| address.port()).unwrap_or(port);
        Ok(Self {
            listener,
            host: host.to_string(),
            port: bound_port,
            pathname: pathname.to_string(),
        })
    }

    /// The port actually bound, which differs from the requested one only when
    /// a test asks for port 0.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Wait for the authorization response and return the whole callback URL.
    ///
    /// Requests for any other path get a 404 and are ignored: a browser
    /// prefetching `/favicon.ico` must not end the wait.
    pub fn wait_for_callback(&self, timeout: Duration) -> Result<String, LoopbackError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if let Some(url) = self.serve(stream) {
                        return Ok(url);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(LoopbackError::Timeout);
                    }
                    std::thread::sleep(POLL_INTERVAL);
                }
                Err(_) => {
                    if Instant::now() >= deadline {
                        return Err(LoopbackError::Timeout);
                    }
                }
            }
        }
    }

    fn serve(&self, mut stream: TcpStream) -> Option<String> {
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let target = read_request_target(&mut stream)?;
        let url = format!("http://{}:{}{}", self.host, self.port, target);
        let path = target.split('?').next().unwrap_or_default();
        if path != self.pathname {
            respond(&mut stream, "404 Not Found", REJECTION_PAGE);
            return None;
        }
        respond(&mut stream, "200 OK", COMPLETION_PAGE);
        Some(url)
    }
}

fn read_request_target(stream: &mut TcpStream) -> Option<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buffer.len() > MAX_REQUEST_BYTES {
            return None;
        }
    }
    let head = String::from_utf8_lossy(&buffer);
    let request_line = head.lines().next()?;
    let mut fields = request_line.split_whitespace();
    let method = fields.next()?;
    let target = fields.next()?;
    if method != "GET" || !target.starts_with('/') {
        return None;
    }
    Some(target.to_string())
}

fn respond(stream: &mut TcpStream, status: &str, page: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/html; charset=utf-8\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}",
        page.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Write);
}
