//! `sv add <pairing-url>` — the whole link flow against a faked machine and
//! relay. The bare verb's other mode, the runbook, lives in `add_command.rs`.
//!
//! The requests are asserted body by body because they are the contract the
//! npm port has to reproduce: the environment server and the relay only accept
//! exactly these shapes, in exactly this order.

mod common;

use std::collections::HashMap;

use serde_json::{Value, json};

use common::{FakeTransport, fixture, json_response};
use svartal::browser::NoBrowser;
use svartal::commands::{self, CliError, Context};
use svartal::config::resolve_config;
use svartal::http::{Body, HttpError, HttpTransport, Request, Response};
use svartal::link::{PairingTarget, parse_pairing_url};
use svartal::store::MemoryTokenStorage;

const PORT: &str = "4100";
const PAIRING_URL: &str = "http://box.local:4100/pair#token=pairing-token-1";
const PAIRING_TOKEN: &str = "pairing-token-1";
const ENVIRONMENT_TOKEN: &str = "env-access-token-1";
const ENVIRONMENT_CREDENTIAL: &str = "env-credential-1";
const GRANTED_SCOPES: &str =
    "orchestration:read orchestration:operate terminal:operate review:write relay:read access:read access:write relay:write";

fn machine_url(path: &str) -> String {
    format!("http://127.0.0.1:{PORT}{path}")
}

fn descriptor_body() -> Value {
    json!({
        "environmentId": "env-box",
        "label": "boxy",
        "platform": { "os": "linux", "arch": "x64" },
        "serverVersion": "1.0.0",
        "capabilities": { "repositoryIdentity": false },
    })
}

fn link_body() -> Value {
    json!({
        "ok": true,
        "cloudUserId": "cloud-user-1",
        "environmentId": "env-box",
        "endpoint": {
            "httpBaseUrl": "https://tunnel.example.test",
            "wsBaseUrl": "wss://tunnel.example.test",
            "providerKind": "cloudflare_tunnel",
        },
        "endpointRuntime": {
            "providerKind": "cloudflare_tunnel",
            "connectorToken": "connector-token-1",
        },
        "relayIssuer": "https://relay.example.test",
        "environmentCredential": ENVIRONMENT_CREDENTIAL,
        "cloudMintPublicKey": "mint-key-pem",
    })
}

struct Harness {
    fixture: Value,
    now: i64,
}

impl Harness {
    fn new() -> Self {
        let fixture = fixture("oidc.json");
        let now = fixture["nowEpochMs"].as_i64().unwrap();
        Self { fixture, now }
    }

    fn relay_url(&self) -> String {
        self.fixture["relayUrl"].as_str().unwrap().to_string()
    }

    fn user_access_token(&self) -> String {
        self.fixture["storedTokens"]["accessToken"].as_str().unwrap().to_string()
    }

    /// The default transport: every step answers, the tunnel client runs.
    /// `overrides` replaces the response for a URL.
    fn transport(&self, overrides: &[(&str, Response)]) -> FakeTransport {
        let issuer = self.fixture["issuer"].as_str().unwrap().to_string();
        let relay = self.relay_url();
        let discovery = self.fixture["discovery"].clone();
        let jwks = self.fixture["jwks"].clone();
        let overrides: HashMap<String, Response> = overrides
            .iter()
            .map(|(url, response)| (url.to_string(), response.clone()))
            .collect();
        FakeTransport::new(move |request| {
            let url = request.url.as_str();
            if let Some(overridden) = overrides.get(url) {
                return overridden.clone();
            }
            if url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &discovery);
            }
            if url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &jwks);
            }
            if url == machine_url("/.well-known/svartal/environment") {
                return json_response(200, &descriptor_body());
            }
            if url == machine_url("/oauth/token") {
                return json_response(
                    200,
                    &json!({
                        "access_token": ENVIRONMENT_TOKEN,
                        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": GRANTED_SCOPES,
                    }),
                );
            }
            if url == format!("{relay}/v1/client/environment-link-challenges") {
                return json_response(
                    200,
                    &json!({ "challenge": "challenge-1", "expiresAt": "2026-08-13T09:05:00Z" }),
                );
            }
            if url == machine_url("/api/connect/link-proof") {
                return json_response(200, &json!("link-proof-jwt-1"));
            }
            if url == format!("{relay}/v1/client/environment-links") {
                return json_response(200, &link_body());
            }
            if url == machine_url("/api/connect/relay-config") {
                return json_response(
                    200,
                    &json!({
                        "ok": true,
                        "endpointRuntimeStatus": {
                            "status": "running",
                            "providerKind": "cloudflare_tunnel",
                            "pid": 42,
                        },
                    }),
                );
            }
            if url == format!("{relay}/v1/environments") {
                return json_response(
                    200,
                    &json!({
                        "environments": [{
                            "environmentId": "env-box",
                            "label": "boxy",
                            "endpoint": {
                                "httpBaseUrl": "https://tunnel.example.test",
                                "wsBaseUrl": "wss://tunnel.example.test",
                                "providerKind": "cloudflare_tunnel",
                            },
                            "linkedAt": "2026-08-13T09:00:00Z",
                        }],
                    }),
                );
            }
            json_response(404, &json!({ "error": "unexpected" }))
        })
    }

    fn run_with(
        &self,
        http: &dyn HttpTransport,
        pairing_url: &str,
    ) -> (Result<(), CliError>, String) {
        let environment = [
            ("HOME".to_string(), "/home/person".to_string()),
            ("SVARTAL_ISSUER".to_string(), self.fixture["issuer"].as_str().unwrap().to_string()),
            ("SVARTAL_RELAY_URL".to_string(), self.relay_url()),
        ]
        .into_iter()
        .collect();
        let storage = MemoryTokenStorage::with_value(&self.fixture["storedTokens"].to_string());
        let now = self.now;
        let clock = move || now;
        let browser = NoBrowser;
        let context = Context {
            config: resolve_config(&environment).unwrap(),
            http,
            storage: &storage,
            browser: &browser,
            now: &clock,
        };
        let mut out: Vec<u8> = Vec::new();
        let outcome = commands::add_link(&context, &mut out, pairing_url);
        (outcome, String::from_utf8(out).unwrap())
    }

    fn run(
        &self,
        overrides: &[(&str, Response)],
        pairing_url: &str,
    ) -> (Result<(), CliError>, String, Vec<Request>) {
        let http = self.transport(overrides);
        let (outcome, output) = self.run_with(&http, pairing_url);
        (outcome, output, http.requests())
    }
}

/// The flow's own requests, with the OIDC issuer traffic (session
/// verification) filtered out.
fn flow_requests(harness: &Harness, requests: &[Request]) -> Vec<Request> {
    let issuer = harness.fixture["issuer"].as_str().unwrap();
    requests.iter().filter(|request| !request.url.starts_with(issuer)).cloned().collect()
}

fn json_body(request: &Request) -> Value {
    match &request.body {
        Some(Body::Json(value)) => value.clone(),
        other => panic!("expected a JSON body on {}, got {other:?}", request.url),
    }
}

fn header(request: &Request, name: &str) -> String {
    request
        .headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| panic!("no {name} header on {}", request.url))
}

/// The two credentials that must never reach a person's terminal.
fn assert_no_secrets(output: &str, outcome: &Result<(), CliError>) {
    let error = match outcome {
        Ok(()) => String::new(),
        Err(error) => error.0.clone(),
    };
    for secret in [PAIRING_TOKEN, ENVIRONMENT_CREDENTIAL] {
        assert!(!output.contains(secret), "stdout leaked {secret}: {output}");
        assert!(!error.contains(secret), "stderr would leak {secret}: {error}");
    }
}

// -- the happy path ---------------------------------------------------------

#[test]
fn add_runs_the_whole_link_flow_in_order_with_the_exact_payloads() {
    let harness = Harness::new();
    let (outcome, output, requests) = harness.run(&[], PAIRING_URL);
    outcome.unwrap();

    let relay = harness.relay_url();
    let flow = flow_requests(&harness, &requests);
    assert_eq!(
        flow.iter().map(|request| (request.method, request.url.as_str())).collect::<Vec<_>>(),
        vec![
            ("GET", machine_url("/.well-known/svartal/environment").as_str()),
            ("POST", machine_url("/oauth/token").as_str()),
            ("POST", format!("{relay}/v1/client/environment-link-challenges").as_str()),
            ("POST", machine_url("/api/connect/link-proof").as_str()),
            ("POST", format!("{relay}/v1/client/environment-links").as_str()),
            ("POST", machine_url("/api/connect/relay-config").as_str()),
            ("GET", format!("{relay}/v1/environments").as_str()),
        ]
    );

    // Step 3: the token exchange, as a form, no scope narrowing.
    let exchange = &flow[1];
    assert_eq!(
        match &exchange.body {
            Some(Body::Form(fields)) => fields.clone(),
            other => panic!("expected a form body, got {other:?}"),
        },
        vec![
            ("grant_type".to_string(), "urn:ietf:params:oauth:grant-type:token-exchange".to_string()),
            ("subject_token".to_string(), PAIRING_TOKEN.to_string()),
            ("subject_token_type".to_string(), "urn:svartal:params:oauth:token-type:environment-bootstrap".to_string()),
            ("requested_token_type".to_string(), "urn:ietf:params:oauth:token-type:access_token".to_string()),
            ("client_label".to_string(), "svartal CLI".to_string()),
            ("client_device_type".to_string(), "desktop".to_string()),
        ]
    );

    // Step 4: the challenge, on the user's own bearer token.
    let user_bearer = format!("Bearer {}", harness.user_access_token());
    assert_eq!(header(&flow[2], "authorization"), user_bearer);
    assert_eq!(
        json_body(&flow[2]),
        json!({
            "notificationsEnabled": true,
            "liveActivitiesEnabled": true,
            "managedTunnelsEnabled": true,
        })
    );

    // Step 5: the link proof, on the environment token, everything loopback.
    let environment_bearer = format!("Bearer {ENVIRONMENT_TOKEN}");
    assert_eq!(header(&flow[3], "authorization"), environment_bearer);
    assert_eq!(
        json_body(&flow[3]),
        json!({
            "challenge": "challenge-1",
            "relayIssuer": relay,
            "endpoint": {
                "httpBaseUrl": format!("http://127.0.0.1:{PORT}"),
                "wsBaseUrl": format!("ws://127.0.0.1:{PORT}"),
                "providerKind": "cloudflare_tunnel",
            },
            "origin": {
                "localHttpHost": "127.0.0.1",
                "localHttpPort": 4100,
            },
        })
    );

    // Step 6: the link itself, proof in, user bearer again.
    assert_eq!(header(&flow[4], "authorization"), user_bearer);
    assert_eq!(
        json_body(&flow[4]),
        json!({
            "proof": "link-proof-jwt-1",
            "notificationsEnabled": true,
            "liveActivitiesEnabled": true,
            "managedTunnelsEnabled": true,
        })
    );

    // Step 7: the relay config the machine stores, the runtime echoed verbatim.
    assert_eq!(header(&flow[5], "authorization"), environment_bearer);
    assert_eq!(
        json_body(&flow[5]),
        json!({
            "relayUrl": relay,
            "relayIssuer": "https://relay.example.test",
            "cloudUserId": "cloud-user-1",
            "environmentCredential": ENVIRONMENT_CREDENTIAL,
            "cloudMintPublicKey": "mint-key-pem",
            "endpointRuntime": {
                "providerKind": "cloudflare_tunnel",
                "connectorToken": "connector-token-1",
            },
        })
    );

    // Step 8: the confirmation listing, user bearer.
    assert_eq!(header(&flow[6], "authorization"), user_bearer);

    // The tunnel reported running, so the one sentence is the whole output.
    assert_eq!(output, "Linked boxy to your Svartal account.\n");
    assert_no_secrets(&output, &Ok(()));
}

#[test]
fn a_tunnel_that_has_not_reported_in_earns_the_second_sentence() {
    let harness = Harness::new();
    let relay_config = machine_url("/api/connect/relay-config");
    let (outcome, output, _) = harness.run(
        &[(
            relay_config.as_str(),
            json_response(200, &json!({ "ok": true, "endpointRuntimeStatus": { "status": "disabled" } })),
        )],
        PAIRING_URL,
    );
    outcome.unwrap();
    assert_eq!(
        output,
        "Linked boxy to your Svartal account.\nsv shell boxy will reach it once its tunnel reports in.\n"
    );
}

#[test]
fn a_machine_without_the_tunnel_client_is_still_linked_and_says_so() {
    let harness = Harness::new();
    let relay_config = machine_url("/api/connect/relay-config");
    let (outcome, output, requests) = harness.run(
        &[(
            relay_config.as_str(),
            json_response(
                503,
                &json!({
                    "_tag": "EnvironmentCloudEndpointUnavailableError",
                    "message": "Managed endpoint runtime could not be started.",
                    "endpointRuntimeStatus": {
                        "status": "failed",
                        "providerKind": "cloudflare_tunnel",
                        "reason": "cloudflared is not installed",
                    },
                }),
            ),
        )],
        PAIRING_URL,
    );
    outcome.unwrap();
    assert_eq!(
        output,
        "Linked boxy to your Svartal account.\nThis machine's tunnel client is not installed yet; the machine will be reachable once it is.\n"
    );
    // The link is still confirmed against the relay afterwards.
    let relay = harness.relay_url();
    assert!(requests.iter().any(|request| request.url == format!("{relay}/v1/environments")));
    assert_no_secrets(&output, &Ok(()));
}

// -- the pairing URL --------------------------------------------------------

#[test]
fn the_pairing_url_host_is_always_rewritten_to_loopback() {
    assert_eq!(
        parse_pairing_url("http://192.168.7.20:4100/pair#token=abc").unwrap(),
        PairingTarget { port: 4100, token: "abc".to_string() }
    );
}

#[test]
fn the_token_may_arrive_in_the_query_instead_of_the_fragment() {
    assert_eq!(
        parse_pairing_url("http://box.local:4100/pair?token=abc").unwrap(),
        PairingTarget { port: 4100, token: "abc".to_string() }
    );
}

#[test]
fn the_hosted_form_takes_its_port_from_the_host_parameter() {
    assert_eq!(
        parse_pairing_url("https://app.svartal.com/pair?host=box.tail1234.ts.net:4100&label=Boxy#token=abc")
            .unwrap(),
        PairingTarget { port: 4100, token: "abc".to_string() }
    );
    assert_eq!(
        parse_pairing_url("https://app.svartal.com/pair?host=http://box.local:5200#token=abc").unwrap(),
        PairingTarget { port: 5200, token: "abc".to_string() }
    );
}

#[test]
fn a_bare_token_is_refused_with_the_shape_of_a_real_pairing_url() {
    let error = parse_pairing_url("pairing-token-1").unwrap_err();
    assert_eq!(
        error.0,
        "That is not a pairing URL. Paste the whole URL the environment server printed at startup, like http://<host>:<port>/pair#token=<token>."
    );
}

#[test]
fn a_pairing_url_without_a_token_says_what_is_missing() {
    let error = parse_pairing_url("http://box.local:4100/pair").unwrap_err();
    assert_eq!(
        error.0,
        "That pairing URL carries no token. Copy the whole URL the environment server printed at startup, including the part after the #."
    );
}

// -- the failures -----------------------------------------------------------

/// A transport whose loopback side never answers: `sv add` run on the wrong
/// machine.
struct MachineUnreachable(FakeTransport);

impl HttpTransport for MachineUnreachable {
    fn send(&self, request: Request) -> Result<Response, HttpError> {
        if request.url.starts_with("http://127.0.0.1:") {
            return Err(HttpError("Connection refused (os error 61)".to_string()));
        }
        self.0.send(request)
    }
}

#[test]
fn an_unreachable_environment_server_says_to_run_this_on_the_machine() {
    let harness = Harness::new();
    let http = MachineUnreachable(harness.transport(&[]));
    let (outcome, output) = harness.run_with(&http, PAIRING_URL);
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "Could not reach the machine's environment server on 127.0.0.1:4100. `sv add` links the machine it runs on, so run it there, or forward the port first with `ssh -L 4100:127.0.0.1:4100 <machine>`."
    );
    assert_eq!(output, "");
    assert_no_secrets(&output, &Err(error));
}

#[test]
fn a_spent_pairing_token_is_named_as_the_cause() {
    let harness = Harness::new();
    let token_url = machine_url("/oauth/token");
    let (outcome, output, _) = harness.run(
        &[(
            token_url.as_str(),
            json_response(401, &json!({ "_tag": "EnvironmentAuthInvalidError", "message": "invalid credential" })),
        )],
        PAIRING_URL,
    );
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "The machine refused the pairing token: each one is single-use and this one is spent, so use a fresh pairing URL (the environment server prints a new one every time it starts) and run `sv add` again."
    );
    assert_no_secrets(&output, &Err(error));
}

#[test]
fn a_pairing_link_without_the_relay_write_scope_is_refused() {
    let harness = Harness::new();
    let token_url = machine_url("/oauth/token");
    let (outcome, output, _) = harness.run(
        &[(
            token_url.as_str(),
            json_response(
                200,
                &json!({
                    "access_token": ENVIRONMENT_TOKEN,
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "orchestration:read orchestration:operate terminal:operate review:write relay:read",
                }),
            ),
        )],
        PAIRING_URL,
    );
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "This pairing link cannot manage the machine's relay connection: use the pairing URL the environment server prints at startup, or one minted with the Manage-relay (relay:write) scope."
    );
    assert_no_secrets(&output, &Err(error));
}

#[test]
fn a_relay_answering_for_another_workspace_is_an_error_and_the_token_is_not_retried() {
    let harness = Harness::new();
    let relay = harness.relay_url();
    let links_url = format!("{relay}/v1/client/environment-links");
    let mut wrong_workspace = link_body();
    wrong_workspace["environmentId"] = json!("env-other");
    let (outcome, output, requests) =
        harness.run(&[(links_url.as_str(), json_response(200, &wrong_workspace))], PAIRING_URL);
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "The relay answered for workspace env-other, but this machine is env-box. The pairing token is spent now, so get a fresh pairing URL (the environment server prints a new one every time it starts) and run `sv add` again."
    );
    // The single-use token was exchanged exactly once; nothing re-ran the burn.
    let token_url = machine_url("/oauth/token");
    assert_eq!(requests.iter().filter(|request| request.url == token_url).count(), 1);
    // Nothing was configured on the machine.
    assert!(!requests.iter().any(|request| request.url == machine_url("/api/connect/relay-config")));
    assert_no_secrets(&output, &Err(error));
}

#[test]
fn a_relay_failure_after_the_burn_says_the_token_is_spent() {
    let harness = Harness::new();
    let relay = harness.relay_url();
    let challenge_url = format!("{relay}/v1/client/environment-link-challenges");
    let (outcome, output, _) = harness.run(
        &[(challenge_url.as_str(), json_response(500, &json!({ "error": "boom" })))],
        PAIRING_URL,
    );
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "Could not get a link challenge from the Svartal relay (the relay returned HTTP 500). The pairing token is spent now, so get a fresh pairing URL (the environment server prints a new one every time it starts) and run `sv add` again."
    );
    assert_no_secrets(&output, &Err(error));
}

#[test]
fn a_machine_that_cannot_store_the_link_says_the_link_itself_exists() {
    let harness = Harness::new();
    let relay_config = machine_url("/api/connect/relay-config");
    let (outcome, output, _) = harness.run(
        &[(
            relay_config.as_str(),
            json_response(500, &json!({ "_tag": "EnvironmentHttpInternalServerError", "message": "boom" })),
        )],
        PAIRING_URL,
    );
    let error = outcome.unwrap_err();
    assert_eq!(
        error.0,
        "Your account is linked to boxy, but the machine could not store the relay configuration (the machine returned HTTP 500). Re-running `sv add` with a fresh pairing token is safe."
    );
    assert_no_secrets(&output, &Err(error));
}
