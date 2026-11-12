//! Project transfer uses fake HTTP only, including token minting.
mod common;

use std::sync::{Arc, Mutex};

use common::{FakeTransport, TempDir, fixture, json_response};
use serde_json::{Value, json};
use svartal::browser::NoBrowser;
use svartal::commands::{CliError, Context};
use svartal::config::resolve_config;
use svartal::http::{Body, Request, Response};
use svartal::project_transfer::{Recipient, parse_transfer_args, transfer};
use svartal::store::MemoryTokenStorage;

const ID: &str = "11111111-1111-4111-8111-111111111111";

fn body(request: &Request) -> Value {
    match &request.body {
        Some(Body::Json(value)) => value.clone(),
        _ => Value::Null,
    }
}

/// Signs in, mints one API token, and answers the transfer with `reply`.
fn run(
    project: &str,
    recipient: Recipient<'_>,
    reply: Response,
) -> (Result<(), CliError>, String, Vec<Request>) {
    let fixture = fixture("oidc.json");
    let f = fixture.clone();
    let reply = Arc::new(Mutex::new(Some(reply)));
    let http = FakeTransport::new(move |request| {
        let issuer = f["issuer"].as_str().unwrap();
        if request.url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &f["discovery"]);
        }
        if request.url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &f["jwks"]);
        }
        if request.url == format!("{issuer}/api/v1/client/tokens") {
            return json_response(
                201,
                &json!({"data": {"id": "token-1", "secret": "secret", "expiresAt": "2026-12-01T00:00:00Z"}}),
            );
        }
        reply
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| panic!("Unexpected request: {} {}", request.method, request.url))
    });
    let dir = TempDir::new("project-transfer");
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let path = dir.path().to_string_lossy().into_owned();
    let environment = [
        ("HOME".into(), path.clone()),
        ("SVARTAL_CONFIG_DIR".into(), path),
        (
            "SVARTAL_ISSUER".into(),
            fixture["issuer"].as_str().unwrap().into(),
        ),
        (
            "SVARTAL_RELAY_URL".into(),
            fixture["relayUrl"].as_str().unwrap().into(),
        ),
        ("SVARTAL_WEB_URL".into(), "https://web.example.test".into()),
    ]
    .into_iter()
    .collect();
    let clock = || fixture["nowEpochMs"].as_i64().unwrap();
    let context = Context {
        config: resolve_config(&environment).unwrap(),
        http: &http,
        storage: &storage,
        browser: &NoBrowser,
        now: &clock,
    };
    let mut out = Vec::new();
    let result = transfer(&context, &mut out, project, recipient);
    let requests = http
        .requests()
        .into_iter()
        .filter(|request| request.url.contains("/transfer"))
        .collect();
    (result, String::from_utf8(out).unwrap(), requests)
}

#[test]
fn to_user_posts_the_username_and_names_the_new_owner() {
    let reply = json_response(
        200,
        &json!({"data": {"id": ID, "slug": "demo", "owner": {"type": "user", "slug": "maintainer"}}}),
    );
    let (result, out, requests) = run("demo", Recipient::User("maintainer"), reply);
    result.unwrap();
    assert_eq!(
        out,
        format!(
            "demo: now owned by maintainer. You keep push access.\nhttps://web.example.test/app/projects/{ID}\n"
        )
    );
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "POST");
    assert!(
        requests[0].url.ends_with("/api/v1/projects/demo/transfer"),
        "{}",
        requests[0].url
    );
    assert_eq!(body(&requests[0]), json!({"user": "maintainer"}));
}

#[test]
fn to_org_posts_the_organization_and_names_it() {
    let reply = json_response(
        200,
        &json!({"data": {"id": ID, "slug": "demo", "owner": null,
                         "organization": {"id": "org-1", "slug": "upstream"}}}),
    );
    let (result, out, requests) = run(ID, Recipient::Organization("upstream"), reply);
    result.unwrap();
    assert!(
        out.starts_with(&format!("{ID}: now owned by upstream.")),
        "{out}"
    );
    assert_eq!(body(&requests[0]), json!({"organization": "upstream"}));
}

#[test]
fn a_slug_collision_reports_the_server_reason() {
    let reply = json_response(
        422,
        &json!({"errors": {"slug": ["has already been taken"]}}),
    );
    let (result, out, _) = run("demo", Recipient::Organization("upstream"), reply);
    let message = result.unwrap_err().to_string();
    assert!(
        message.contains("Could not transfer the project"),
        "{message}"
    );
    assert!(message.contains("already been taken"), "{message}");
    assert!(out.is_empty());
}

#[test]
fn arguments_need_exactly_one_new_owner() {
    assert_eq!(
        parse_transfer_args(&["transfer", "demo"], Some("maintainer"), None),
        Ok(("demo", Recipient::User("maintainer")))
    );
    assert_eq!(
        parse_transfer_args(&["transfer", "demo"], None, Some("upstream")),
        Ok(("demo", Recipient::Organization("upstream")))
    );
    assert!(parse_transfer_args(&["transfer", "demo"], None, None).is_err());
    assert!(parse_transfer_args(&["transfer", "demo"], Some("a"), Some("b")).is_err());
    assert!(parse_transfer_args(&["transfer"], Some("a"), None).is_err());
    assert!(parse_transfer_args(&["visibility", "demo"], Some("a"), None).is_err());
}
