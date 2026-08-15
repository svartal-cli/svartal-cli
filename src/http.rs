//! The one place this CLI talks to the network.
//!
//! Everything above it takes a `&dyn HttpTransport`, for the same reason the
//! TypeScript CLI injects `fetch`: the OIDC flow, the API listings and the
//! relay calls are then testable without a socket, and the tests exercise the
//! real request bodies rather than a stub of them.

use std::io::Read as _;
use std::time::Duration;

use serde_json::Value;

/// Bodies are small JSON documents and JWT sets. A megabyte is far more than
/// any of them, and refusing more keeps a hostile or broken endpoint from
/// filling memory.
pub const MAX_RESPONSE_BYTES: u64 = 1_048_576;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct HttpError(pub String);

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for HttpError {}

#[derive(Debug, Clone)]
pub enum Body {
    /// `application/x-www-form-urlencoded`, the OAuth token endpoint's shape.
    Form(Vec<(String, String)>),
    Json(Value),
}

#[derive(Debug, Clone)]
pub struct Request {
    pub method: &'static str,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Body>,
}

impl Request {
    pub fn get(url: impl Into<String>) -> Self {
        Self { method: "GET", url: url.into(), headers: Vec::new(), body: None }
    }

    pub fn post(url: impl Into<String>) -> Self {
        Self { method: "POST", url: url.into(), headers: Vec::new(), body: None }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    pub fn form(mut self, fields: &[(&str, &str)]) -> Self {
        self.body = Some(Body::Form(
            fields.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())).collect(),
        ));
        self
    }

    pub fn json(mut self, value: Value) -> Self {
        self.body = Some(Body::Json(value));
        self
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

impl Response {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Result<Value, HttpError> {
        serde_json::from_slice(&self.body)
            .map_err(|error| HttpError(format!("the response was not valid JSON: {error}")))
    }
}

pub trait HttpTransport {
    /// A non-2xx status is a `Response`, not an error. Only a request that
    /// never produced a status — DNS, TLS, a dropped connection — is an
    /// `HttpError`, because that is the boundary the OIDC rules in `ID-26`
    /// draw between "try again" and "sign in again".
    fn send(&self, request: Request) -> Result<Response, HttpError>;
}

pub struct UreqTransport {
    agent: ureq::Agent,
}

impl UreqTransport {
    pub fn new() -> Self {
        Self { agent: ureq::AgentBuilder::new().timeout(REQUEST_TIMEOUT).build() }
    }
}

impl Default for UreqTransport {
    fn default() -> Self {
        Self::new()
    }
}

fn read_body(response: ureq::Response) -> Result<Vec<u8>, HttpError> {
    let mut body = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE_BYTES + 1)
        .read_to_end(&mut body)
        .map_err(|error| HttpError(format!("the response could not be read: {error}")))?;
    if body.len() as u64 > MAX_RESPONSE_BYTES {
        return Err(HttpError("the response was too large".to_string()));
    }
    Ok(body)
}

impl HttpTransport for UreqTransport {
    fn send(&self, request: Request) -> Result<Response, HttpError> {
        let mut built = self.agent.request(request.method, &request.url);
        for (name, value) in &request.headers {
            built = built.set(name, value);
        }
        let sent = match &request.body {
            None => built.call(),
            Some(Body::Form(fields)) => {
                let borrowed: Vec<(&str, &str)> =
                    fields.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect();
                built.send_form(&borrowed)
            }
            Some(Body::Json(value)) => built.send_json(value.clone()),
        };
        match sent {
            Ok(response) => {
                let status = response.status();
                Ok(Response { status, body: read_body(response)? })
            }
            Err(ureq::Error::Status(status, response)) => {
                Ok(Response { status, body: read_body(response)? })
            }
            Err(error) => Err(HttpError(format!("{error}"))),
        }
    }
}
