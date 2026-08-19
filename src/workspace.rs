//! The two workspace HTTP calls between the relay's connect response and the
//! WebSocket.
//!
//! Port of `packages/client-runtime/src/authorization/remote.ts`
//! (`exchangeRemoteDpopAccessToken`, `resolveRemoteDpopWebSocketConnectionUrl`)
//! as `connectRemoteEnvironment` drives them:
//!
//! 1. `POST {httpBaseUrl}/oauth/token` — the relay's short-lived environment
//!    credential becomes an environment access token carrying the scopes.
//! 2. `POST {httpBaseUrl}/api/auth/websocket-ticket` — that token becomes a
//!    one-time ticket, which goes on the socket URL as `?wsTicket=`.
//!
//! Both are DPoP-bound. The ticket call presents the access token, so its proof
//! must carry the token's `ath`; a proof made without it is refused.

use serde::Deserialize;
use url::Url;

use crate::http::{HttpTransport, Request};

/// `AuthTokenExchangeGrantType`.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
/// `AuthEnvironmentBootstrapTokenType`.
pub const BOOTSTRAP_TOKEN_TYPE: &str = "urn:svartal:params:oauth:token-type:environment-bootstrap";
/// `AuthAccessTokenType`.
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

/// `AuthTerminalOperateScope`.
pub const TERMINAL_OPERATE_SCOPE: &str = "terminal:operate";
/// `AuthOrchestrationReadScope`.
///
/// Not for the terminal. The workspace gates its initial-config subscription
/// behind it, and that subscription is where the CLI learns the workspace root
/// to open the shell in. Deployed servers enforce this today, so a
/// terminal-only token cannot finish connecting.
pub const ORCHESTRATION_READ_SCOPE: &str = "orchestration:read";

/// The scopes `sv shell` asks for, in the order the TypeScript CLI sends
/// them. Both are load-bearing; see `ORCHESTRATION_READ_SCOPE`.
pub const SHELL_SCOPES: [&str; 2] = [TERMINAL_OPERATE_SCOPE, ORCHESTRATION_READ_SCOPE];

/// The one scope `sv close` asks for. Closing never reads the workspace
/// config — there is no cwd to learn — so `orchestration:read` stays out of
/// the token: every terminal call, the metadata read included, is gated on
/// `terminal:operate` alone.
pub const CLOSE_SCOPES: [&str; 1] = [TERMINAL_OPERATE_SCOPE];

#[derive(Debug)]
pub enum WorkspaceError {
    /// The workspace refused the terminal scope while handing out the access
    /// token — the machine's grant saying this person may not have a terminal
    /// here, before any terminal call is made.
    TerminalNotAllowed { label: String },
    Failed { label: String, detail: String },
}

impl std::fmt::Display for WorkspaceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TerminalNotAllowed { label } => write!(
                f,
                "Your grant on {label} does not allow terminals. Ask whoever manages that machine to allow terminal access for your account, then try again."
            ),
            Self::Failed { label, detail } => {
                write!(f, "Could not open a shell on {label}: {detail}")
            }
        }
    }
}

impl std::error::Error for WorkspaceError {}

#[derive(Debug, Clone, Deserialize)]
pub struct AccessToken {
    pub access_token: String,
    pub token_type: String,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WebSocketTicket {
    pub ticket: String,
}

/// `client_label` / `client_device_type` reported to the workspace's session
/// list, so a person looking at their machine sees what connected.
#[derive(Debug, Clone, Copy)]
pub struct ClientMetadata {
    pub label: &'static str,
    pub device_type: &'static str,
}

pub const CLI_CLIENT_METADATA: ClientMetadata =
    ClientMetadata { label: "svartal CLI", device_type: "desktop" };

/// `environmentEndpointUrl(httpBaseUrl, "/oauth/token")`.
pub fn token_url(http_base_url: &str) -> Result<String, WorkspaceError> {
    join(http_base_url, "/oauth/token")
}

pub fn websocket_ticket_url(http_base_url: &str) -> Result<String, WorkspaceError> {
    join(http_base_url, "/api/auth/websocket-ticket")
}

fn join(base: &str, path: &str) -> Result<String, WorkspaceError> {
    Url::parse(base)
        .and_then(|base| base.join(path))
        .map(|url| url.to_string())
        .map_err(|error| WorkspaceError::Failed {
            label: base.to_string(),
            detail: format!("the workspace endpoint is not a URL: {error}"),
        })
}

/// `EnvironmentScopeRequiredError`, or the invalid-scope shapes of
/// `EnvironmentRequestInvalidError`. Both mean the grant does not cover
/// terminals.
fn is_terminal_scope_refusal(body: &serde_json::Value) -> bool {
    let tag = body.get("_tag").and_then(serde_json::Value::as_str).unwrap_or_default();
    if tag == "EnvironmentScopeRequiredError" {
        return true;
    }
    if tag != "EnvironmentRequestInvalidError" {
        return false;
    }
    matches!(
        body.get("reason").and_then(serde_json::Value::as_str),
        Some("scope_not_granted") | Some("invalid_scope")
    )
}

/// Exchange the relay's environment credential for a workspace access token.
pub fn exchange_access_token(
    http: &dyn HttpTransport,
    input: &TokenExchange<'_>,
) -> Result<AccessToken, WorkspaceError> {
    let url = token_url(input.http_base_url)?;
    let scope = input.scopes.join(" ");
    let response = http
        .send(
            Request::post(url)
                .header("dpop", input.dpop_proof)
                .header("accept", "application/json")
                .form(&[
                    ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
                    ("subject_token", input.credential),
                    ("subject_token_type", BOOTSTRAP_TOKEN_TYPE),
                    ("requested_token_type", ACCESS_TOKEN_TYPE),
                    ("scope", scope.as_str()),
                    ("client_label", input.client_metadata.label),
                    ("client_device_type", input.client_metadata.device_type),
                ]),
        )
        .map_err(|error| WorkspaceError::Failed {
            label: input.label.to_string(),
            detail: error.to_string(),
        })?;
    if !response.is_success() {
        let body = response.json().unwrap_or(serde_json::Value::Null);
        if is_terminal_scope_refusal(&body) {
            return Err(WorkspaceError::TerminalNotAllowed { label: input.label.to_string() });
        }
        return Err(WorkspaceError::Failed {
            label: input.label.to_string(),
            detail: format!("the workspace returned HTTP {} to the token exchange.", response.status),
        });
    }
    let token: AccessToken = decode(&response, input.label)?;
    if token.access_token.trim().is_empty() {
        return Err(WorkspaceError::Failed {
            label: input.label.to_string(),
            detail: "the workspace returned an empty access token.".to_string(),
        });
    }
    Ok(token)
}

pub struct TokenExchange<'a> {
    pub http_base_url: &'a str,
    /// What the person typed, for the error messages.
    pub label: &'a str,
    /// The short-lived environment credential from the relay's connect response.
    pub credential: &'a str,
    pub scopes: &'a [&'a str],
    pub dpop_proof: &'a str,
    pub client_metadata: ClientMetadata,
}

/// Take a one-time WebSocket ticket with the workspace access token.
pub fn issue_websocket_ticket(
    http: &dyn HttpTransport,
    http_base_url: &str,
    label: &str,
    access_token: &str,
    dpop_proof: &str,
) -> Result<WebSocketTicket, WorkspaceError> {
    let url = websocket_ticket_url(http_base_url)?;
    let response = http
        .send(
            Request::post(url)
                .header("authorization", &format!("DPoP {access_token}"))
                .header("dpop", dpop_proof)
                .header("accept", "application/json"),
        )
        .map_err(|error| WorkspaceError::Failed {
            label: label.to_string(),
            detail: error.to_string(),
        })?;
    if !response.is_success() {
        return Err(WorkspaceError::Failed {
            label: label.to_string(),
            detail: format!(
                "the workspace returned HTTP {} to the WebSocket ticket request.",
                response.status
            ),
        });
    }
    decode(&response, label)
}

/// `resolveRemoteDpopWebSocketConnectionUrl`: the ws base URL, with `/ws` when
/// it carries no path of its own, and the ticket in the query.
pub fn websocket_url(ws_base_url: &str, ticket: &str) -> Result<String, WorkspaceError> {
    let mut url = Url::parse(ws_base_url).map_err(|error| WorkspaceError::Failed {
        label: ws_base_url.to_string(),
        detail: format!("the workspace WebSocket URL is not a URL: {error}"),
    })?;
    if url.path().is_empty() || url.path() == "/" {
        url.set_path("/ws");
    }
    url.query_pairs_mut().clear().append_pair("wsTicket", ticket);
    Ok(url.to_string())
}

/// The ws base URL a caller falls back to when the relay reported none:
/// `httpBaseUrl` with an ws scheme.
pub fn default_ws_base_url(http_base_url: &str) -> Result<String, WorkspaceError> {
    let mut url = Url::parse(http_base_url).map_err(|error| WorkspaceError::Failed {
        label: http_base_url.to_string(),
        detail: format!("the workspace endpoint is not a URL: {error}"),
    })?;
    let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
    url.set_scheme(scheme).map_err(|()| WorkspaceError::Failed {
        label: http_base_url.to_string(),
        detail: "the workspace endpoint scheme cannot be a WebSocket one.".to_string(),
    })?;
    Ok(url.to_string())
}

fn decode<T: for<'de> Deserialize<'de>>(
    response: &crate::http::Response,
    label: &str,
) -> Result<T, WorkspaceError> {
    let value = response.json().map_err(|error| WorkspaceError::Failed {
        label: label.to_string(),
        detail: error.to_string(),
    })?;
    serde_json::from_value(value).map_err(|error| WorkspaceError::Failed {
        label: label.to_string(),
        detail: format!("the workspace answered with something this client cannot read: {error}"),
    })
}
