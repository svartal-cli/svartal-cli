//! The two relay calls, over a real socket.
//!
//! The relay is faked in-process, the same shape brok's tests use, and the
//! requests go through the production `ureq` transport — so these tests
//! exercise the real headers, the real form body and the real JSON body, not a
//! description of them.

use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use svartal::dpop::{DpopKey, PrivateJwk, ProofRequest, normalize_htu};
use svartal::http::UreqTransport;
use svartal::jwt::b64url_decode;
use svartal::relay::{
    self, ACCESS_TOKEN_TYPE, ConnectRequest, JWT_SUBJECT_TOKEN_TYPE, RelayError, TokenExchange,
    TOKEN_EXCHANGE_GRANT_TYPE,
};

struct Received {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

type Log = Arc<Mutex<Vec<Received>>>;

/// A one-request-at-a-time HTTP server that answers from `router`.
fn fake_relay(router: impl Fn(&str, &str) -> (u16, Value) + Send + 'static) -> (String, Log) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let recorded = log.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 4096];
            let head_end = loop {
                let Ok(read) = stream.read(&mut chunk) else { return };
                if read == 0 {
                    break None;
                }
                buffer.extend_from_slice(&chunk[..read]);
                if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
                    break Some(end);
                }
            };
            let Some(head_end) = head_end else { continue };
            let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
            let mut lines = head.lines();
            let request_line = lines.next().unwrap_or_default().to_string();
            let mut fields = request_line.split_whitespace();
            let method = fields.next().unwrap_or_default().to_string();
            let path = fields.next().unwrap_or_default().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|line| line.split_once(':'))
                .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
                .collect();
            let length: usize = headers
                .iter()
                .find(|(name, _)| name == "content-length")
                .and_then(|(_, value)| value.parse().ok())
                .unwrap_or(0);
            let mut body = buffer[head_end + 4..].to_vec();
            while body.len() < length {
                let Ok(read) = stream.read(&mut chunk) else { break };
                if read == 0 {
                    break;
                }
                body.extend_from_slice(&chunk[..read]);
            }
            let body = String::from_utf8_lossy(&body).to_string();
            let (status, payload) = router(&method, &path);
            let payload = serde_json::to_string(&payload).unwrap();
            let response = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{payload}",
                payload.len()
            );
            let _ = stream.write_all(response.as_bytes());
            recorded.lock().unwrap().push(Received { method, path, headers, body });
        }
    });
    (format!("http://127.0.0.1:{port}"), log)
}

fn key() -> DpopKey {
    let jwk: PrivateJwk = serde_json::from_str(
        r#"{"kty":"EC","crv":"P-256","x":"gIM9Zyiqs6b9rsCD1rnUWlY4KdbMG0_ZoiN-o3R5-dE","y":"mXO03LW1mqi7gU76vC6EYr7p4SsPHAPY1eiQPt0IiSc","d":"E5fWojxBXygO15oCGp0gdiy1vZ71-cPnMnL-4Ttv6GI"}"#,
    )
    .unwrap();
    DpopKey::from_private_jwk(&jwk).unwrap()
}

fn header<'a>(received: &'a Received, name: &str) -> Option<&'a str> {
    received.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
}

fn form_field(body: &str, name: &str) -> Option<String> {
    url::form_urlencoded::parse(body.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
}

fn proof_claims(proof: &str) -> Value {
    let payload = proof.split('.').nth(1).unwrap();
    serde_json::from_slice(&b64url_decode(payload).unwrap()).unwrap()
}

#[test]
fn the_token_exchange_sends_the_contract_body_and_the_proof() {
    let (relay_url, log) = fake_relay(|_, _| {
        (
            200,
            json!({
                "access_token": "relay-access-token",
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": "environment:connect",
            }),
        )
    });
    let key = key();
    let url = relay::token_url(&relay_url);
    let proof = key
        .create_proof(&ProofRequest {
            method: "POST",
            url: &url,
            access_token: None,
            jti: "11111111-0000-4000-8000-000000000001",
            issued_at_seconds: 1_785_412_800,
        })
        .unwrap();
    let http = UreqTransport::new();

    let token = relay::exchange_access_token(
        &http,
        &TokenExchange {
            relay_url: &relay_url,
            client_id: "svartal-cli",
            subject_token: "the-oidc-access-token",
            dpop_proof: &proof,
        },
    )
    .unwrap();

    assert_eq!(token.access_token, "relay-access-token");
    assert_eq!(token.token_type, "DPoP");
    let log = log.lock().unwrap();
    let received = log.first().unwrap();
    assert_eq!(received.method, "POST");
    assert_eq!(received.path, "/v1/client/dpop-token");
    assert_eq!(header(received, "dpop").unwrap(), proof);
    assert_eq!(header(received, "accept").unwrap(), "application/json");
    assert_eq!(form_field(&received.body, "grant_type").unwrap(), TOKEN_EXCHANGE_GRANT_TYPE);
    assert_eq!(form_field(&received.body, "subject_token").unwrap(), "the-oidc-access-token");
    assert_eq!(form_field(&received.body, "subject_token_type").unwrap(), JWT_SUBJECT_TOKEN_TYPE);
    assert_eq!(form_field(&received.body, "requested_token_type").unwrap(), ACCESS_TOKEN_TYPE);
    assert_eq!(form_field(&received.body, "resource").unwrap(), relay_url);
    assert_eq!(form_field(&received.body, "scope").unwrap(), "environment:connect");
    assert_eq!(form_field(&received.body, "client_id").unwrap(), "svartal-cli");

    // The proof is bound to the URL the request actually went to.
    assert_eq!(proof_claims(&proof)["htu"].as_str().unwrap(), normalize_htu(&url).unwrap());
    assert_eq!(proof_claims(&proof)["htm"].as_str().unwrap(), "POST");
}

#[test]
fn a_relay_that_does_not_know_this_client_says_so_rather_than_blaming_the_sign_in() {
    for status in [400u16, 401, 403] {
        let (relay_url, _log) = fake_relay(move |_, _| (status, json!({ "error": "invalid_client" })));
        let http = UreqTransport::new();
        let error = relay::exchange_access_token(
            &http,
            &TokenExchange {
                relay_url: &relay_url,
                client_id: "svartal-cli",
                subject_token: "token",
                dpop_proof: "proof",
            },
        )
        .unwrap_err();
        assert!(matches!(error, RelayError::ClientRefused { .. }), "HTTP {status}");
        assert!(error.to_string().contains("refused the svartal-cli client"));
        assert!(error.to_string().contains("not enabled on this relay yet"));
    }
}

#[test]
fn connect_carries_the_thumbprint_and_the_dpop_bound_token() {
    let (relay_url, log) = fake_relay(|_, _| {
        (
            200,
            json!({
                "environmentId": "env-primary",
                "endpoint": {
                    "httpBaseUrl": "https://workspace.example.test",
                    "wsBaseUrl": "wss://workspace.example.test",
                    "providerKind": "cloudflare_tunnel",
                },
                "credential": "environment-credential",
                "expiresAt": "2026-08-15T12:00:00Z",
            }),
        )
    });
    let key = key();
    let url = relay::connect_url(&relay_url, "env-primary");
    let proof = key
        .create_proof(&ProofRequest {
            method: "POST",
            url: &url,
            access_token: Some("relay-access-token"),
            jti: "11111111-0000-4000-8000-000000000002",
            issued_at_seconds: 1_785_412_800,
        })
        .unwrap();
    let http = UreqTransport::new();

    let connection = relay::connect_environment(
        &http,
        &ConnectRequest {
            relay_url: &relay_url,
            environment_id: "env-primary",
            label: "Primary",
            access_token: "relay-access-token",
            dpop_proof: &proof,
            thumbprint: key.thumbprint(),
            device_id: None,
        },
    )
    .unwrap();

    assert_eq!(connection.environment_id, "env-primary");
    assert_eq!(connection.credential, "environment-credential");
    assert_eq!(connection.endpoint.ws_base_url, "wss://workspace.example.test");

    let log = log.lock().unwrap();
    let received = log.first().unwrap();
    assert_eq!(received.path, "/v1/environments/env-primary/connect");
    assert_eq!(header(received, "authorization").unwrap(), "DPoP relay-access-token");
    assert_eq!(header(received, "dpop").unwrap(), proof);
    let body: Value = serde_json::from_str(&received.body).unwrap();
    assert_eq!(body, json!({ "clientProofKeyThumbprint": key.thumbprint() }));

    // `ath` binds the proof to the token presented with it.
    let claims = proof_claims(&proof);
    assert_eq!(
        claims["ath"].as_str().unwrap(),
        svartal::dpop::access_token_hash("relay-access-token")
    );
    assert_eq!(claims["htu"].as_str().unwrap(), url);
}

#[test]
fn a_workspace_the_relay_will_not_connect_you_to_is_named_in_the_message() {
    for (status, expected) in [
        (404u16, "does not know a workspace called Primary"),
        (403, "would not connect you to Primary"),
    ] {
        let (relay_url, _log) = fake_relay(move |_, _| (status, json!({})));
        let http = UreqTransport::new();
        let error = relay::connect_environment(
            &http,
            &ConnectRequest {
                relay_url: &relay_url,
                environment_id: "env-primary",
                label: "Primary",
                access_token: "token",
                dpop_proof: "proof",
                thumbprint: "thumb",
                device_id: None,
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains(expected), "HTTP {status}: {error}");
    }
}

#[test]
fn a_relay_token_this_client_cannot_use_is_refused() {
    let (relay_url, _log) = fake_relay(|_, _| {
        (
            200,
            json!({
                // A bearer token where a DPoP-bound one was asked for.
                "access_token": "relay-access-token",
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "environment:connect",
            }),
        )
    });
    let http = UreqTransport::new();
    let error = relay::exchange_access_token(
        &http,
        &TokenExchange {
            relay_url: &relay_url,
            client_id: "svartal-cli",
            subject_token: "token",
            dpop_proof: "proof",
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("cannot use"));
}

#[test]
fn the_environment_id_is_escaped_into_the_path() {
    assert_eq!(
        relay::connect_url("https://relay.example.com", "env/../admin"),
        "https://relay.example.com/v1/environments/env%2F..%2Fadmin/connect"
    );
}
