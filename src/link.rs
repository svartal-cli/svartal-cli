//! The client half of `sv add`: linking the machine this command runs on to
//! the signed-in Svartal account.
//!
//! Port of the client-driven flow in `apps/web/src/cloud/linkEnvironment.ts`
//! (`linkPrimaryEnvironmentToCloud`), driven from outside the machine instead
//! of from the web app that runs on it:
//!
//! 1. Parse the pairing URL the environment server printed at startup
//!    (`buildPairingUrl` in `apps/server/src/startupAccess.ts`), or the hosted
//!    `?host=` form (`readHostedPairingRequest`).
//! 2. `GET /.well-known/svartal/environment` — who is this machine.
//! 3. `POST /oauth/token` — exchange the single-use pairing token for an
//!    environment access token. This burns the token: nothing before this
//!    point may be repeated with the same URL.
//! 4. `POST {relay}/v1/client/environment-link-challenges` — user bearer.
//! 5. `POST /api/connect/link-proof` — the environment signs the challenge.
//!    Only the environment server holds the signing key, and it refuses the
//!    call unless it arrives on its own loopback origin. That is why every
//!    request here goes to `127.0.0.1`: `sv add` must run on the machine being
//!    added (or through an `ssh -L` port forward), never across the network.
//! 6. `POST {relay}/v1/client/environment-links` — user bearer, proof in.
//! 7. `POST /api/connect/relay-config` — the machine stores its credentials.
//!
//! The flow itself, with the sentences each failure earns, is `commands::add`.

use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;

use crate::http::{HttpTransport, Request};
use crate::workspace::{
    ACCESS_TOKEN_TYPE, BOOTSTRAP_TOKEN_TYPE, CLI_CLIENT_METADATA, TOKEN_EXCHANGE_GRANT_TYPE,
};

/// `AuthRelayWriteScope`. The link proof and the relay config are gated behind
/// it, and only the startup pairing credential (or one minted with the
/// Manage-relay scope) carries it.
pub const RELAY_WRITE_SCOPE: &str = "relay:write";

/// `MANAGED_ENDPOINT_PROVIDER_KIND` in `linkEnvironment.ts`.
pub const MANAGED_PROVIDER_KIND: &str = "cloudflare_tunnel";

#[derive(Debug)]
pub struct AddError(pub String);

impl std::fmt::Display for AddError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for AddError {}

/// What a pairing URL resolves to. Only the port survives the parse: the proof
/// call refuses non-loopback callers, so whatever host the URL named, the
/// requests go to `127.0.0.1` on that port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairingTarget {
    pub port: u16,
    pub token: String,
}

impl PairingTarget {
    pub fn http_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn ws_base_url(&self) -> String {
        format!("ws://127.0.0.1:{}", self.port)
    }
}

const NOT_A_PAIRING_URL: &str = "That is not a pairing URL. Paste the whole URL the environment server printed at startup, like http://<host>:<port>/pair#token=<token>.";
const NO_TOKEN_IN_URL: &str = "That pairing URL carries no token. Copy the whole URL the environment server printed at startup, including the part after the #.";

/// `getPairingTokenFromUrl`: the fragment wins, the query is the fallback.
fn pairing_token(url: &Url) -> Option<String> {
    let from_fragment = url.fragment().and_then(|fragment| {
        url::form_urlencoded::parse(fragment.as_bytes())
            .find(|(name, _)| name == "token")
            .map(|(_, value)| value.trim().to_string())
    });
    if let Some(token) = from_fragment.filter(|token| !token.is_empty()) {
        return Some(token);
    }
    url.query_pairs()
        .find(|(name, _)| name == "token")
        .map(|(_, value)| value.trim().to_string())
        .filter(|token| !token.is_empty())
}

/// `normalizeRemoteBaseUrl`: a bare `host:port` means `https://host:port`.
fn port_of_host_value(host: &str) -> Option<u16> {
    let trimmed = host.trim().trim_start_matches('/');
    let with_scheme = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    Url::parse(&with_scheme).ok()?.port_or_known_default()
}

/// Parse the pairing URL: the direct `http://<host>:<port>/pair#token=…` form
/// the environment server prints, or the hosted `…/pair?host=<host>` form the
/// static web app links to. Either way the answer is a loopback port and the
/// single-use token.
pub fn parse_pairing_url(input: &str) -> Result<PairingTarget, AddError> {
    let url = Url::parse(input.trim()).map_err(|_| AddError(NOT_A_PAIRING_URL.to_string()))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AddError(NOT_A_PAIRING_URL.to_string()));
    }
    let token = pairing_token(&url).ok_or_else(|| AddError(NO_TOKEN_IN_URL.to_string()))?;
    let hosted = url
        .query_pairs()
        .find(|(name, _)| name == "host")
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let port = match hosted {
        Some(host) => {
            port_of_host_value(&host).ok_or_else(|| AddError(NOT_A_PAIRING_URL.to_string()))?
        }
        None => url
            .port_or_known_default()
            .ok_or_else(|| AddError(NOT_A_PAIRING_URL.to_string()))?,
    };
    Ok(PairingTarget { port, token })
}

/// The two descriptor fields `sv add` needs: which workspace this machine is,
/// and what to call it in every sentence that follows.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnvironmentDescriptor {
    pub environment_id: String,
    pub label: String,
}

/// `GET /.well-known/svartal/environment` (`EnvironmentMetadataHttpApi`). No auth:
/// this is the same discovery every client starts with.
pub fn discover_environment(
    http: &dyn HttpTransport,
    target: &PairingTarget,
) -> Result<EnvironmentDescriptor, AddError> {
    let unreachable = || {
        AddError(format!(
            "Could not reach the machine's environment server on 127.0.0.1:{port}. `sv add` links the machine it runs on, so run it there, or forward the port first with `ssh -L {port}:127.0.0.1:{port} <machine>`.",
            port = target.port
        ))
    };
    let response = http
        .send(
            Request::get(format!("{}/.well-known/svartal/environment", target.http_base_url()))
                .header("accept", "application/json"),
        )
        .map_err(|_| unreachable())?;
    if !response.is_success() {
        return Err(unreachable());
    }
    let value = response.json().map_err(|_| unreachable())?;
    serde_json::from_value(value).map_err(|_| unreachable())
}

/// The environment access token step 3 grants, held in memory only. The
/// pairing token is spent the moment the exchange is attempted, so everything
/// after runs on this.
#[derive(Debug, Clone)]
pub struct EnvironmentToken {
    pub access_token: String,
    scopes: Vec<String>,
}

impl EnvironmentToken {
    pub fn allows_relay_write(&self) -> bool {
        self.scopes.iter().any(|scope| scope == RELAY_WRITE_SCOPE)
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ExchangedToken {
    access_token: String,
    scope: String,
}

/// `POST /oauth/token`, the same token-exchange grant `sv shell` sends to a
/// workspace (`workspace::exchange_access_token`), with the pairing token as
/// the subject and no requested scope, so the grant's own scopes come back and
/// can be checked for `relay:write`. No DPoP: the token lives for this one
/// command and never leaves the process.
pub fn exchange_pairing_token(
    http: &dyn HttpTransport,
    target: &PairingTarget,
) -> Result<EnvironmentToken, AddError> {
    let fresh_url = "(the environment server prints a new one every time it starts)";
    let url = format!("{}/oauth/token", target.http_base_url());
    let response = http
        .send(Request::post(url).header("accept", "application/json").form(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT_TYPE),
            ("subject_token", target.token.as_str()),
            ("subject_token_type", BOOTSTRAP_TOKEN_TYPE),
            ("requested_token_type", ACCESS_TOKEN_TYPE),
            ("client_label", CLI_CLIENT_METADATA.label),
            ("client_device_type", CLI_CLIENT_METADATA.device_type),
        ]))
        .map_err(|error| {
            AddError(format!(
                "Could not exchange the pairing token with the machine ({error}), so use a fresh pairing URL {fresh_url} and run `sv add` again."
            ))
        })?;
    if response.status == 401 || response.status == 403 {
        return Err(AddError(format!(
            "The machine refused the pairing token: each one is single-use and this one is spent, so use a fresh pairing URL {fresh_url} and run `sv add` again."
        )));
    }
    if !response.is_success() {
        return Err(AddError(format!(
            "Could not exchange the pairing token with the machine (it returned HTTP {}), so use a fresh pairing URL {fresh_url} and run `sv add` again.",
            response.status
        )));
    }
    let unreadable = || {
        AddError(format!(
            "Could not exchange the pairing token with the machine (its answer was not readable), so use a fresh pairing URL {fresh_url} and run `sv add` again."
        ))
    };
    let token: ExchangedToken = response
        .json()
        .map_err(|_| unreadable())
        .and_then(|value| serde_json::from_value(value).map_err(|_| unreadable()))?;
    Ok(EnvironmentToken {
        access_token: token.access_token,
        scopes: token.scope.split_whitespace().map(str::to_string).collect(),
    })
}

/// What went wrong inside one post-burn step; `commands::add` wraps it in the
/// sentence that says the pairing token is spent.
#[derive(Debug)]
pub struct StepFailure(pub String);

fn post_json(
    http: &dyn HttpTransport,
    url: String,
    bearer: &str,
    body: Value,
    who: &str,
) -> Result<Value, StepFailure> {
    let response = http
        .send(
            Request::post(url)
                .header("authorization", &format!("Bearer {bearer}"))
                .header("accept", "application/json")
                .json(body),
        )
        .map_err(|error| StepFailure(error.to_string()))?;
    if !response.is_success() {
        return Err(StepFailure(format!("{who} returned HTTP {}", response.status)));
    }
    response.json().map_err(|_| StepFailure(format!("{who} answered with something this client cannot read")))
}

/// Step 4: `POST {relay}/v1/client/environment-link-challenges`, plain user
/// bearer — the relay's client group takes the OIDC access token without DPoP.
pub fn create_link_challenge(
    http: &dyn HttpTransport,
    relay_url: &str,
    user_access_token: &str,
) -> Result<String, StepFailure> {
    let body = post_json(
        http,
        format!("{relay_url}/v1/client/environment-link-challenges"),
        user_access_token,
        json!({
            "notificationsEnabled": true,
            "liveActivitiesEnabled": true,
            "managedTunnelsEnabled": true,
        }),
        "the relay",
    )?;
    match body.get("challenge").and_then(Value::as_str) {
        Some(challenge) if !challenge.is_empty() => Ok(challenge.to_string()),
        _ => Err(StepFailure("the relay answered without a challenge".to_string())),
    }
}

/// Step 5: `POST /api/connect/link-proof`. The endpoint and origin mirror
/// `linkEnvironment.ts` exactly, both pinned to the loopback origin the
/// environment server itself accepts.
pub fn request_link_proof(
    http: &dyn HttpTransport,
    target: &PairingTarget,
    environment_token: &str,
    relay_url: &str,
    challenge: &str,
) -> Result<String, StepFailure> {
    let body = post_json(
        http,
        format!("{}/api/connect/link-proof", target.http_base_url()),
        environment_token,
        json!({
            "challenge": challenge,
            "relayIssuer": relay_url,
            "endpoint": {
                "httpBaseUrl": target.http_base_url(),
                "wsBaseUrl": target.ws_base_url(),
                "providerKind": MANAGED_PROVIDER_KIND,
            },
            "origin": {
                "localHttpHost": "127.0.0.1",
                "localHttpPort": target.port,
            },
        }),
        "the machine",
    )?;
    match body.as_str() {
        Some(proof) if !proof.is_empty() => Ok(proof.to_string()),
        _ => Err(StepFailure("the machine answered without a link proof".to_string())),
    }
}

/// `RelayEnvironmentLinkResponse`, the fields the rest of the flow needs.
/// `endpointRuntime` stays raw JSON because step 7 echoes it back verbatim.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkedEnvironment {
    pub cloud_user_id: String,
    pub environment_id: String,
    pub relay_issuer: String,
    pub environment_credential: String,
    pub cloud_mint_public_key: String,
    #[serde(default)]
    pub endpoint_runtime: Value,
}

/// Step 6: `POST {relay}/v1/client/environment-links`, user bearer, proof in.
pub fn link_environment(
    http: &dyn HttpTransport,
    relay_url: &str,
    user_access_token: &str,
    proof: &str,
) -> Result<LinkedEnvironment, StepFailure> {
    let body = post_json(
        http,
        format!("{relay_url}/v1/client/environment-links"),
        user_access_token,
        json!({
            "proof": proof,
            "notificationsEnabled": true,
            "liveActivitiesEnabled": true,
            "managedTunnelsEnabled": true,
        }),
        "the relay",
    )?;
    serde_json::from_value(body)
        .map_err(|_| StepFailure("the relay answered with something this client cannot read".to_string()))
}

/// What step 7 said about the machine's tunnel client, which decides the
/// closing sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelReport {
    /// `endpointRuntimeStatus.status == "running"`: reachable now.
    Running,
    /// `"failed"` or `"unsupported"`: the link exists, but the relay client is
    /// not installed on the machine yet.
    NotInstalled,
    /// Anything else (a `"disabled"` runtime, an old server): promise nothing.
    Unspecified,
}

fn runtime_status(body: &Value) -> Option<&str> {
    body.get("endpointRuntimeStatus")?.get("status")?.as_str()
}

/// Step 7: `POST /api/connect/relay-config` — the machine stores the relay
/// credentials from step 6. A 503 `EnvironmentCloudEndpointUnavailableError`
/// whose status says the runtime failed is not a failed link: the relay-side
/// link from step 6 exists, the machine just has no tunnel client to start.
pub fn configure_relay(
    http: &dyn HttpTransport,
    target: &PairingTarget,
    environment_token: &str,
    relay_url: &str,
    linked: &LinkedEnvironment,
) -> Result<TunnelReport, StepFailure> {
    let response = http
        .send(
            Request::post(format!("{}/api/connect/relay-config", target.http_base_url()))
                .header("authorization", &format!("Bearer {environment_token}"))
                .header("accept", "application/json")
                .json(json!({
                    "relayUrl": relay_url,
                    "relayIssuer": linked.relay_issuer,
                    "cloudUserId": linked.cloud_user_id,
                    "environmentCredential": linked.environment_credential,
                    "cloudMintPublicKey": linked.cloud_mint_public_key,
                    "endpointRuntime": linked.endpoint_runtime,
                })),
        )
        .map_err(|error| StepFailure(error.to_string()))?;
    let body = response.json().unwrap_or(Value::Null);
    match runtime_status(&body) {
        Some("running") if response.is_success() => Ok(TunnelReport::Running),
        Some("failed" | "unsupported") => Ok(TunnelReport::NotInstalled),
        _ if response.is_success() => Ok(TunnelReport::Unspecified),
        _ => Err(StepFailure(format!("the machine returned HTTP {}", response.status))),
    }
}
