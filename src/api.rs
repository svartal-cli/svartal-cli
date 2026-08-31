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
    /// Whether a server exists for this machine right now: `"running"`,
    /// `"hibernated"`, `"waking"`, `"hibernating"`, `"failed"`. Absent from an
    /// older Svartal, which is why it is optional and treated as running.
    pub runtime_state: Option<String>,
    pub last_seen_at: Option<String>,
    pub environments: Vec<Workspace>,
}

/// What Svartal says about a machine somebody has asked for.
///
/// One shape for every outcome so the CLI prints one story: it is up, it is
/// coming up, or somebody else has the last slot and you are in line.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineTicket {
    /// `"active"`, `"waking"`, `"queued"`, `"asleep"`, `"failed"`, `"always_on"`.
    pub state: String,
    pub machine_id: Option<String>,
    pub machine_name: Option<String>,
    pub position: Option<u32>,
    pub eta_seconds: Option<u64>,
    pub reason: Option<String>,
}

impl MachineTicket {
    /// Whether this machine is usable now.
    pub fn ready(&self) -> bool {
        matches!(self.state.as_str(), "active" | "always_on")
    }

    /// Whether waiting will get somewhere.
    pub fn settling(&self) -> bool {
        matches!(self.state.as_str(), "waking" | "queued")
    }

    /// What to print while waiting. Plain, and true for each state.
    pub fn sentence(&self, label: &str) -> String {
        match self.state.as_str() {
            "active" | "always_on" => format!("{label} is ready."),
            "waking" => match self.eta_seconds {
                Some(seconds) if seconds >= 60 => {
                    format!("Starting {label}. This takes about {} minutes.", seconds.div_ceil(60))
                }
                _ => format!("Starting {label}."),
            },
            "queued" => match self.position {
                Some(position) if position > 1 => format!(
                    "Every machine in the pool is in use. {} people are ahead of you.",
                    position - 1
                ),
                _ => "Every machine in the pool is in use. You are next.".to_string(),
            },
            "asleep" => format!("{label} is asleep."),
            "failed" => match self.reason.as_deref() {
                Some(reason) => format!("{label} could not be started: {reason}"),
                None => format!("{label} could not be started."),
            },
            other => format!("{label}: {other}"),
        }
    }
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

/// Asks Svartal to make one machine usable, and says what happened.
///
/// Idempotent: asking twice while a machine is coming up does not start a
/// second one, so it is safe to call before every connection.
pub fn wake_machine(
    http: &dyn HttpTransport,
    api_base_url: &str,
    access_token: &str,
    machine_id: &str,
) -> Result<MachineTicket, ApiError> {
    let action = "start this machine";
    send_ticket(
        http,
        Request::post(format!("{api_base_url}/api/v1/client/machines/{machine_id}/wake")),
        access_token,
        action,
    )
}

/// What is happening with one machine, without asking for anything.
///
/// Polling must never wake a machine: somebody watching a list should not be
/// paying for servers by looking at them.
pub fn machine_activation(
    http: &dyn HttpTransport,
    api_base_url: &str,
    access_token: &str,
    machine_id: &str,
) -> Result<MachineTicket, ApiError> {
    let action = "read this machine's state";
    send_ticket(
        http,
        Request::get(format!("{api_base_url}/api/v1/client/machines/{machine_id}/activation")),
        access_token,
        action,
    )
}

fn send_ticket(
    http: &dyn HttpTransport,
    request: Request,
    access_token: &str,
    action: &str,
) -> Result<MachineTicket, ApiError> {
    let response = http
        .send(
            request
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
    let body: Value = response
        .json()
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })?;
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
