//! The two relay calls that stand between a Svartal sign-in and a workspace.
//!
//! 1. `POST /v1/client/dpop-token` exchanges the OIDC access token for a relay
//!    access token bound to this CLI's proof key.
//! 2. `POST /v1/environments/:id/connect` turns that token into a workspace
//!    endpoint and a short-lived environment credential.
//!
//! Port of `src/relay.ts`. Everything after step 2 — the workspace token
//! exchange, the WebSocket and the terminal RPC — is phase 2.
//!
//! Neither function sees key material: the proof arrives already signed, the
//! same discipline the TypeScript module follows.

use serde::Deserialize;
use serde_json::json;

use crate::api::ManagedEndpoint;
use crate::http::{HttpTransport, Request};

/// The only scope a terminal user needs from the relay: permission to connect.
pub const ENVIRONMENT_CONNECT_SCOPE: &str = "environment:connect";
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub const JWT_SUBJECT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
pub const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug)]
pub enum RelayError {
    /// The relay keeps an allowlist of client ids. A relay that has not been
    /// updated to know `svartal-cli` refuses the exchange for everyone, so this
    /// is almost never the fault of the person running the command.
    ClientRefused { client_id: String, status: u16 },
    ConnectRefused { label: String, status: u16 },
    Unavailable { action: String, detail: String },
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClientRefused { client_id, .. } => write!(
                f,
                "The Svartal relay refused the {client_id} client. Terminal connections are not enabled on this relay yet, so `svartal shell` cannot reach a workspace from here."
            ),
            Self::ConnectRefused { label, status } if *status == 404 => write!(
                f,
                "The Svartal relay does not know a workspace called {label}. Run `svartal machines` to see what you can reach."
            ),
            Self::ConnectRefused { label, .. } => write!(
                f,
                "The Svartal relay would not connect you to {label}. Your link to that workspace may have been removed."
            ),
            Self::Unavailable { action, detail } => write!(f, "Could not {action}: {detail}"),
        }
    }
}

impl std::error::Error for RelayError {}

#[derive(Debug, Clone, Deserialize)]
pub struct DpopAccessToken {
    pub access_token: String,
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: i64,
    pub scope: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentConnection {
    pub environment_id: String,
    pub endpoint: ManagedEndpoint,
    pub credential: String,
    pub expires_at: String,
}

/// The token-exchange URL, exported because the request and its DPoP proof have
/// to agree on it exactly.
pub fn token_url(relay_url: &str) -> String {
    format!("{relay_url}/v1/client/dpop-token")
}

/// The URL both the request and its DPoP proof have to agree on.
pub fn connect_url(relay_url: &str, environment_id: &str) -> String {
    format!("{relay_url}/v1/environments/{}/connect", encode_path_segment(environment_id))
}

pub struct TokenExchange<'a> {
    pub relay_url: &'a str,
    pub client_id: &'a str,
    /// The OIDC access token from the local credential.
    pub subject_token: &'a str,
    pub dpop_proof: &'a str,
}

/// Exchange the Svartal sign-in for a relay access token bound to the proof
/// key's thumbprint.
pub fn exchange_access_token(
    http: &dyn HttpTransport,
    input: &TokenExchange<'_>,
) -> Result<DpopAccessToken, RelayError> {
    let url = token_url(input.relay_url);
    let response = http
        .send(
            Request::post(url)
                .header("dpop", input.dpop_proof)
                .header("accept", "application/json")
                .form(&[
                    ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
                    ("subject_token", input.subject_token),
                    ("subject_token_type", JWT_SUBJECT_TOKEN_TYPE),
                    ("requested_token_type", ACCESS_TOKEN_TYPE),
                    ("resource", input.relay_url),
                    ("scope", ENVIRONMENT_CONNECT_SCOPE),
                    ("client_id", input.client_id),
                ]),
        )
        .map_err(|error| RelayError::Unavailable {
            action: "reach the Svartal relay".to_string(),
            detail: error.to_string(),
        })?;

    // 400 is what an unknown client id looks like on an OAuth token endpoint,
    // and 401/403 is what a rejected one looks like. All three mean the same
    // thing here, and none of them is fixed by signing in again.
    if response.status == 400 || response.status == 401 || response.status == 403 {
        return Err(RelayError::ClientRefused {
            client_id: input.client_id.to_string(),
            status: response.status,
        });
    }
    if !response.is_success() {
        return Err(RelayError::Unavailable {
            action: "get a Svartal relay token".to_string(),
            detail: format!("the relay returned HTTP {}.", response.status),
        });
    }
    let body = response.json().map_err(|error| RelayError::Unavailable {
        action: "read the Svartal relay token".to_string(),
        detail: error.to_string(),
    })?;
    let token: DpopAccessToken =
        serde_json::from_value(body).map_err(|error| RelayError::Unavailable {
            action: "read the Svartal relay token".to_string(),
            detail: error.to_string(),
        })?;
    if token.token_type != "DPoP"
        || token.issued_token_type != ACCESS_TOKEN_TYPE
        || token.access_token.trim().is_empty()
        || token.expires_in <= 0
    {
        return Err(RelayError::Unavailable {
            action: "read the Svartal relay token".to_string(),
            detail: "the relay returned a token this client cannot use.".to_string(),
        });
    }
    Ok(token)
}

pub struct ConnectRequest<'a> {
    pub relay_url: &'a str,
    pub environment_id: &'a str,
    /// What the person typed, for the error messages.
    pub label: &'a str,
    pub access_token: &'a str,
    pub dpop_proof: &'a str,
    /// Binds the returned credential to the same key the proof was signed
    /// with, which is what lets the workspace mint a bound token from it later.
    pub thumbprint: &'a str,
    pub device_id: Option<&'a str>,
}

pub fn connect_environment(
    http: &dyn HttpTransport,
    input: &ConnectRequest<'_>,
) -> Result<EnvironmentConnection, RelayError> {
    let url = connect_url(input.relay_url, input.environment_id);
    let mut body = json!({ "clientProofKeyThumbprint": input.thumbprint });
    if let Some(device_id) = input.device_id {
        body.as_object_mut()
            .expect("body is an object")
            .insert("deviceId".to_string(), json!(device_id));
    }
    let response = http
        .send(
            Request::post(url)
                .header("authorization", &format!("DPoP {}", input.access_token))
                .header("dpop", input.dpop_proof)
                .header("accept", "application/json")
                .json(body),
        )
        .map_err(|error| RelayError::Unavailable {
            action: "reach the Svartal relay".to_string(),
            detail: error.to_string(),
        })?;
    if response.status == 401 || response.status == 403 || response.status == 404 {
        return Err(RelayError::ConnectRefused {
            label: input.label.to_string(),
            status: response.status,
        });
    }
    if !response.is_success() {
        return Err(RelayError::Unavailable {
            action: format!("connect to {}", input.label),
            detail: format!("the relay returned HTTP {}.", response.status),
        });
    }
    let value = response.json().map_err(|error| RelayError::Unavailable {
        action: format!("read the connection details for {}", input.label),
        detail: error.to_string(),
    })?;
    serde_json::from_value(value).map_err(|error| RelayError::Unavailable {
        action: format!("read the connection details for {}", input.label),
        detail: error.to_string(),
    })
}

fn encode_path_segment(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'.'
                || byte == b'~'
            {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}
