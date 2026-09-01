//! The two read-only listings `machines` and `sessions` are built from.
//!
//! Port of `src/api.ts`. A machine record says a workspace container exists; a
//! relay link says this person can actually reach it. Both are needed before
//! the CLI claims anything is reachable, so both are fetched.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::http::{HttpTransport, Request};

#[derive(Debug)]
pub enum ApiError {
    /// The request failed, or the answer was not the shape it should be.
    Failed { action: String, detail: String },
    /// `401`/`403`. Signing in again is the fix, so say so.
    Unauthorized { action: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { action, .. } => write!(f, "Could not {action}."),
            Self::Unauthorized { action } => write!(
                f,
                "Svartal refused the request to {action}. Run `sv login` and try again."
            ),
        }
    }
}

impl std::error::Error for ApiError {}

/// A workspace container on a machine. `environmentId` is the id the relay
/// links people to, so it is the join key between the Svartal API's machine
/// view and the relay's "what am I linked to" view.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Workspace {
    pub id: String,
    pub environment_id: String,
    pub label: Option<String>,
    pub kind: Option<String>,
    pub lifecycle_state: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Machine {
    pub id: String,
    pub name: String,
    pub origin: Option<String>,
    pub lifecycle_state: Option<String>,
    /// `"online"`, `"offline"`, or `"unknown"` when the box never checked in.
    pub presence: String,
    pub last_seen_at: Option<String>,
    pub environments: Vec<Workspace>,
}

/// `RelayManagedEndpoint`. Modelled rather than passed through as raw JSON so
/// `--json` prints the fields in the contract's order, which is what the
/// TypeScript CLI prints after decoding.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedEndpoint {
    pub http_base_url: String,
    pub ws_base_url: String,
    pub provider_kind: String,
}

/// One relay link. Field order matches the contract struct, so `--json`
/// reproduces what the TypeScript CLI prints.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkRecord {
    pub environment_id: String,
    pub label: String,
    pub endpoint: ManagedEndpoint,
    pub linked_at: String,
}

fn fetch_json(
    http: &dyn HttpTransport,
    url: &str,
    access_token: &str,
    action: &str,
) -> Result<Value, ApiError> {
    let response = http
        .send(
            Request::get(url)
                .header("authorization", &format!("Bearer {access_token}"))
                .header("accept", "application/json"),
        )
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })?;
    if response.status == 401 || response.status == 403 {
        return Err(ApiError::Unauthorized { action: action.to_string() });
    }
    if !response.is_success() {
        return Err(ApiError::Failed {
            action: action.to_string(),
            detail: format!("Svartal returned HTTP {}.", response.status),
        });
    }
    response
        .json()
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })
}

/// Machines and the workspaces on them that the signed-in person may reach.
///
/// This is the first-party client surface (`/api/v1/client/...`), which is the
/// only part of the Svartal API an OIDC access token authenticates. The
/// operator surface under `/api/v1/machines` needs a Svartal API token and
/// deliberately does not accept this credential.
pub fn list_machines(
    http: &dyn HttpTransport,
    api_base_url: &str,
    access_token: &str,
) -> Result<Vec<Machine>, ApiError> {
    let action = "list your machines";
    let body = fetch_json(
        http,
        &format!("{api_base_url}/api/v1/client/machines"),
        access_token,
        action,
    )?;
    let data = body.get("data").cloned().unwrap_or(Value::Null);
    serde_json::from_value(data).map_err(|error| ApiError::Failed {
        action: action.to_string(),
        detail: error.to_string(),
    })
}

/// The environments this identity is linked to on the relay.
pub fn list_linked_environments(
    http: &dyn HttpTransport,
    relay_url: &str,
    access_token: &str,
) -> Result<Vec<LinkRecord>, ApiError> {
    let action = "list your linked workspaces";
    let body = fetch_json(http, &format!("{relay_url}/v1/environments"), access_token, action)?;
    let environments = body.get("environments").cloned().unwrap_or(Value::Null);
    serde_json::from_value(environments).map_err(|error| ApiError::Failed {
        action: action.to_string(),
        detail: error.to_string(),
    })
}
