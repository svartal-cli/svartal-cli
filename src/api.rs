//! The two read-only listings `machines` and `sessions` are built from.
//!
//! Port of `src/api.ts`. A machine record says a workspace container exists; a
//! relay link says this person can actually reach it. Both are needed before
//! the CLI claims anything is reachable, so both are fetched.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::commands::{CliError, Context};
use crate::http::{HttpTransport, Request};
use crate::store::{ApiTokenFile, StoredApiToken};

#[derive(Debug)]
pub enum ApiError {
    /// The request failed, or the answer was not the shape it should be.
    Failed { action: String, detail: String },
    /// `401`/`403`. Signing in again is the fix, so say so.
    Unauthorized { action: String },
    /// Any other non-2xx answer, with whatever Svartal said about it. The
    /// sentence carries the detail because for a write ("bundle not found",
    /// "title is required") the detail is the whole point.
    Refused { action: String, status: u16, detail: Option<String> },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { action, .. } => write!(f, "Could not {action}."),
            Self::Unauthorized { action } => write!(
                f,
                "Svartal refused the request to {action}. Run `sv login` and try again."
            ),
            Self::Refused { action, status, detail: Some(detail) } => {
                write!(f, "Could not {action}: {detail} (HTTP {status}).")
            }
            Self::Refused { action, status, detail: None } => {
                write!(f, "Could not {action}: Svartal returned HTTP {status}.")
            }
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

// ---------------------------------------------------------------------------
// The Svartal API proper (`/api/v1/*`), reached with a minted API token.

/// What the minted token may do: read and write projects, which covers
/// issues, bundle links and transcripts. Nothing about machines or account.
pub const API_TOKEN_SCOPES: [&str; 2] = ["project:read", "project:write"];
/// Svartal's own default and its client-token maximum is a year; ninety days
/// keeps a forgotten laptop's token from outliving its usefulness by much.
pub const API_TOKEN_EXPIRES_IN_DAYS: u32 = 90;

/// A successful answer: the status (a transcript post says 201 for new and
/// 200 for one Svartal already had) and the decoded body, `Null` for an empty
/// one such as a 204.
#[derive(Debug, Clone)]
pub struct ApiReply {
    pub status: u16,
    pub body: Value,
}

/// The `detail` sentence Svartal puts in its error bodies, when there is one:
/// `{"errors": {"detail": "..."}}`, or a validation map `{"errors": {"title":
/// ["can't be blank"]}}`, or a plain `{"error": "..."}`.
fn error_detail(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    if let Some(detail) = value.pointer("/errors/detail").and_then(Value::as_str) {
        return Some(detail.to_string());
    }
    if let Some(error) = value.get("error").and_then(Value::as_str) {
        return Some(error.to_string());
    }
    let errors = value.get("errors")?.as_object()?;
    let mut lines: Vec<String> = Vec::new();
    for (field, messages) in errors {
        match messages {
            Value::Array(items) => {
                for item in items.iter().filter_map(Value::as_str) {
                    lines.push(format!("{field} {item}"));
                }
            }
            Value::String(text) => lines.push(format!("{field} {text}")),
            _ => {}
        }
    }
    if lines.is_empty() { None } else { Some(lines.join("; ")) }
}

fn api_token_name() -> String {
    match crate::host::local_hostname() {
        Some(hostname) => format!("sv on {}", hostname.trim_end_matches(".local")),
        None => "sv".to_string(),
    }
}

/// `POST /api/v1/client/tokens` with the OIDC session: a fresh API token,
/// written to the token file before it is returned so the next command finds
/// it. The old file, if any, is replaced; Svartal keeps the old token alive
/// until it expires, which is the price of not having its id any more only
/// when the file was unreadable.
pub fn mint_api_token(context: &Context<'_>) -> Result<StoredApiToken, CliError> {
    let action = "mint a Svartal API token";
    let session = context.current_session()?;
    let response = context
        .http
        .send(
            Request::post(format!("{}/api/v1/client/tokens", context.config.api_base_url))
                .header("authorization", &format!("Bearer {}", session.access_token))
                .header("accept", "application/json")
                .json(json!({
                    "name": api_token_name(),
                    "scopes": API_TOKEN_SCOPES,
                    "expiresInDays": API_TOKEN_EXPIRES_IN_DAYS,
                })),
        )
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })
        .map_err(CliError::of)?;
    if response.status == 401 || response.status == 403 {
        return Err(CliError::of(ApiError::Unauthorized { action: action.to_string() }));
    }
    if !response.is_success() {
        return Err(CliError::of(ApiError::Refused {
            action: action.to_string(),
            status: response.status,
            detail: error_detail(&response.body),
        }));
    }
    let body = response.json().map_err(CliError::of)?;
    let data = body.get("data").cloned().unwrap_or(Value::Null);
    let text = |field: &str| data.get(field).and_then(Value::as_str).map(str::to_string);
    let (Some(id), Some(secret)) = (text("id"), text("secret")) else {
        return Err(CliError(format!("Could not {action}: Svartal answered without a token.")));
    };
    let token = StoredApiToken { version: 1, id, secret, expires_at: text("expiresAt") };
    ApiTokenFile::new(&context.config.state_directory).write(&token).map_err(CliError::of)?;
    Ok(token)
}

/// The stored API token's secret, minted first when there is none or the one
/// on disk is about to expire.
pub fn ensure_api_token(context: &Context<'_>) -> Result<String, CliError> {
    let file = ApiTokenFile::new(&context.config.state_directory);
    if let Some(token) = file.read().map_err(CliError::of)?
        && token.usable_at((context.now)())
    {
        return Ok(token.secret);
    }
    Ok(mint_api_token(context)?.secret)
}

/// One authenticated call under `{api_base_url}/api/v1`. `path` starts with
/// `/`, `action` is the verb phrase an error sentence names ("post the
/// issue"). A 401 — the token was revoked in the web app, or expired on a
/// clock this program did not see — is answered by minting once and sending
/// again; a second refusal is reported as one.
pub fn api_request(
    context: &Context<'_>,
    method: &'static str,
    path: &str,
    body: Option<Value>,
    action: &str,
) -> Result<ApiReply, CliError> {
    let url = format!("{}/api/v1{path}", context.config.api_base_url);
    let mut secret = ensure_api_token(context)?;
    let mut minted_again = false;
    loop {
        let mut request = Request { method, url: url.clone(), headers: Vec::new(), body: None }
            .header("authorization", &format!("Bearer {secret}"))
            .header("accept", "application/json");
        if let Some(value) = body.clone() {
            request = request.json(value);
        }
        let response = context
            .http
            .send(request)
            .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })
            .map_err(CliError::of)?;
        if response.status == 401 && !minted_again {
            minted_again = true;
            secret = mint_api_token(context)?.secret;
            continue;
        }
        if response.status == 401 || response.status == 403 {
            return Err(CliError::of(ApiError::Unauthorized { action: action.to_string() }));
        }
        if !response.is_success() {
            return Err(CliError::of(ApiError::Refused {
                action: action.to_string(),
                status: response.status,
                detail: error_detail(&response.body),
            }));
        }
        let value = if response.body.iter().all(u8::is_ascii_whitespace) {
            Value::Null
        } else {
            response.json().map_err(CliError::of)?
        };
        return Ok(ApiReply { status: response.status, body: value });
    }
}

/// What `sv logout` did about the API token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiTokenRevocation {
    /// There was no token file.
    Absent,
    /// Svartal revoked the token and the file is gone.
    Revoked,
    /// The file is gone, but Svartal did not confirm the revocation; the
    /// token expires on its own.
    NotConfirmed(String),
}

/// `DELETE /api/v1/tokens/:id`, authenticated with the token itself, then the
/// file is removed whatever Svartal said: a person signing out wants the
/// credential off this computer first, and a token Svartal would not revoke
/// still expires.
pub fn revoke_api_token(context: &Context<'_>) -> Result<ApiTokenRevocation, CliError> {
    let file = ApiTokenFile::new(&context.config.state_directory);
    let Some(token) = file.read().map_err(CliError::of)? else {
        return Ok(ApiTokenRevocation::Absent);
    };
    let outcome = context.http.send(
        Request::delete(format!("{}/api/v1/tokens/{}", context.config.api_base_url, token.id))
            .header("authorization", &format!("Bearer {}", token.secret))
            .header("accept", "application/json"),
    );
    file.remove().map_err(CliError::of)?;
    Ok(match outcome {
        Ok(response) if response.is_success() => ApiTokenRevocation::Revoked,
        // Already revoked or gone on Svartal's side: nothing left to revoke.
        Ok(response) if response.status == 404 || response.status == 401 => ApiTokenRevocation::Revoked,
        Ok(response) => ApiTokenRevocation::NotConfirmed(format!("Svartal returned HTTP {}", response.status)),
        Err(error) => ApiTokenRevocation::NotConfirmed(error.to_string()),
    })
}
