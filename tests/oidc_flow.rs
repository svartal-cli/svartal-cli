//! The identity flow, against tokens signed by `jose` — the same library the
//! reference client verifies with.
//!
//! `tests/fixtures/oidc.json` holds the provider's discovery document, its
//! JWKS and every token these tests need, all with a pinned clock. Regenerate
//! with:
//!   node tests/fixtures/generate-oidc.mjs tests/fixtures <ivaldi>/packages/svartal-cli
//!
//! Each test names the requirement it covers.

mod common;

use serde_json::{Value, json};
use url::Url;

use common::{FakeTransport, fixture, form_value, json_response};
use svartal::config::{Config, LoopbackRedirect, resolve_config};
use svartal::oidc::{OidcClient, OidcConfig, Recovery, Transaction};
use svartal::store::{MemoryTokenStorage, StoredTokens, TokenStorage};

const REDIRECT_URI: &str = "http://127.0.0.1:5733/auth/callback";

fn config(fixture: &Value) -> Config {
    let environment = [
        ("HOME".to_string(), "/home/person".to_string()),
        ("SVARTAL_ISSUER".to_string(), fixture["issuer"].as_str().unwrap().to_string()),
        ("SVARTAL_RELAY_URL".to_string(), fixture["relayUrl"].as_str().unwrap().to_string()),
    ]
    .into_iter()
    .collect();
    resolve_config(&environment).unwrap()
}

fn oidc_config(fixture: &Value) -> OidcConfig {
    let config = config(fixture);
    let redirect = LoopbackRedirect {
        redirect_uri: REDIRECT_URI.to_string(),
        host: "127.0.0.1".to_string(),
        port: 5733,
        pathname: "/auth/callback".to_string(),
    };
    OidcConfig::from_cli(&config, &redirect)
}

/// The provider: discovery, JWKS, the token endpoint and revocation.
fn provider(fixture: Value, token_response: Value) -> FakeTransport {
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &fixture["jwks"]);
        }
        if url == format!("{issuer}/oauth/token") {
            return json_response(200, &token_response);
        }
        if url == format!("{issuer}/oauth/revoke") {
            return json_response(200, &json!({}));
        }
        json_response(404, &json!({ "error": "unexpected" }))
    })
}

fn transaction(fixture: &Value, created_at_epoch_ms: i64) -> Transaction {
    Transaction {
        state: "fixture-state".to_string(),
        nonce: fixture["nonce"].as_str().unwrap().to_string(),
        verifier: "fixture-verifier-2Zq8sVrGkC8ZzWq1yYbXn4pLd7eTfHj".to_string(),
        created_at_epoch_ms,
    }
}

fn callback(query: &str) -> String {
    format!("{REDIRECT_URI}?{query}")
}

// -- ID-10: the authorization request -------------------------------------

#[test]
fn authorization_url_carries_every_required_parameter() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::new();
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let authorization = client.begin_authorization().unwrap();
    let url = Url::parse(&authorization.url).unwrap();
    let parameters: Vec<(String, String)> = url
        .query_pairs()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect();
    let names: Vec<&str> = parameters.iter().map(|(name, _)| name.as_str()).collect();

    assert_eq!(url.origin(), Url::parse(fixture["issuer"].as_str().unwrap()).unwrap().origin());
    assert_eq!(url.path(), "/oauth/authorize");
    assert_eq!(
        names,
        vec![
            "client_id",
            "redirect_uri",
            "response_type",
            "scope",
            "state",
            "nonce",
            "code_challenge",
            "code_challenge_method"
        ]
    );
    let value = |name: &str| form_value(&parameters, name).unwrap();
    assert_eq!(value("client_id"), "svartal-cli");
    assert_eq!(value("redirect_uri"), REDIRECT_URI);
    assert_eq!(value("response_type"), "code");
    assert_eq!(value("scope"), "openid profile email offline_access");
    assert_eq!(value("code_challenge_method"), "S256");

    // ID-10: state, nonce and the verifier are 32 random bytes, base64url, and
    // the challenge is the SHA-256 of the verifier.
    for name in ["state", "nonce"] {
        assert_eq!(svartal::jwt::b64url_decode(&value(name)).unwrap().len(), 32);
    }
    assert_eq!(
        svartal::jwt::b64url_decode(&authorization.transaction.verifier).unwrap().len(),
        32
    );
    assert_eq!(
        value("code_challenge"),
        svartal::jwt::b64url_encode(&svartal::oidc::sha256(
            authorization.transaction.verifier.as_bytes()
        ))
    );
    assert_eq!(value("state"), authorization.transaction.state);
    assert_eq!(value("nonce"), authorization.transaction.nonce);
}

// -- ID-14, ID-15, ID-16, ID-18, ID-20: the code exchange -----------------

#[test]
fn code_exchange_verifies_and_stores_the_session() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::new();
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let session = client
        .complete_authorization(transaction(&fixture, now - 1_000), &callback("code=the-code&state=fixture-state"))
        .unwrap();

    assert_eq!(session.user.sub, fixture["subject"].as_str().unwrap());
    assert_eq!(session.user.preferred_username.as_deref(), Some("person"));
    assert_eq!(session.user.email.as_deref(), Some("person@example.test"));
    assert_eq!(session.user.picture, None);

    // ID-14: the exact form body.
    let issuer = fixture["issuer"].as_str().unwrap();
    let form = http.last_form(&format!("{issuer}/oauth/token"));
    assert_eq!(form_value(&form, "grant_type").unwrap(), "authorization_code");
    assert_eq!(form_value(&form, "code").unwrap(), "the-code");
    assert_eq!(form_value(&form, "redirect_uri").unwrap(), REDIRECT_URI);
    assert_eq!(form_value(&form, "client_id").unwrap(), "svartal-cli");
    assert_eq!(form_value(&form, "code_verifier").unwrap(), transaction(&fixture, 0).verifier);

    // ID-20: the stored set, and ID-18: the earlier of the two expiries. The
    // fixture's `exp` (now + 3000s) is earlier than `now + expires_in` would be
    // only when they differ; here they agree, which is what the client stores.
    let stored = StoredTokens::parse(&storage.read().unwrap().unwrap()).unwrap();
    assert_eq!(stored.version, 1);
    assert_eq!(stored.issuer, issuer);
    assert_eq!(stored.client_id, "svartal-cli");
    assert_eq!(stored.scopes, vec!["openid", "profile", "email", "offline_access"]);
    assert_eq!(stored.refresh_token, "refresh-token-1");
    assert_eq!(
        stored.access_expires_at_epoch_ms,
        fixture["accessExpiresAtEpochMs"].as_i64().unwrap()
    );
    assert_eq!(stored.user.sub, fixture["subject"].as_str().unwrap());
}

#[test]
fn stored_file_is_the_shape_the_npm_cli_writes() {
    let fixture = fixture("oidc.json");
    let stored = StoredTokens::parse(&fixture["storedTokens"].to_string()).unwrap();
    let round_tripped: Value = serde_json::from_str(&stored.to_json()).unwrap();
    assert_eq!(round_tripped, fixture["storedTokens"]);
    // Key order too: the file is shared with the npm CLI, so it is written the
    // same way, not merely parsed the same way.
    assert_eq!(stored.to_json(), fixture["storedTokens"].to_string());
}

// -- ID-13: callback rules -------------------------------------------------

#[test]
fn callback_rules_are_enforced_before_the_code_is_spent() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let cases: Vec<(&str, String, i64)> = vec![
        ("a different state", callback("code=c&state=someone-elses"), now - 1_000),
        ("two states", callback("code=c&state=fixture-state&state=fixture-state"), now - 1_000),
        ("error and code together", callback("code=c&error=denied&state=fixture-state"), now - 1_000),
        ("only an error", callback("error=access_denied&state=fixture-state"), now - 1_000),
        ("no code at all", callback("state=fixture-state"), now - 1_000),
        ("another path", "http://127.0.0.1:5733/other?code=c&state=fixture-state".to_string(), now - 1_000),
        ("another port", "http://127.0.0.1:5734/auth/callback?code=c&state=fixture-state".to_string(), now - 1_000),
        ("a fragment", format!("{REDIRECT_URI}?code=c&state=fixture-state#x"), now - 1_000),
        ("an expired transaction", callback("code=c&state=fixture-state"), now - 11 * 60 * 1_000),
        ("a transaction from the future", callback("code=c&state=fixture-state"), now + 120_000),
    ];
    for (label, callback_url, created_at) in cases {
        let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
        let storage = MemoryTokenStorage::new();
        let clock = move || now;
        let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();
        let outcome =
            client.complete_authorization(transaction(&fixture, created_at), &callback_url);
        assert!(outcome.is_err(), "{label} was accepted");
        assert_eq!(http.count(&format!("{issuer}/oauth/token")), 0, "{label} reached the token endpoint");
    }
}

// -- ID-16: local verification --------------------------------------------

#[test]
fn every_rejected_token_is_refused() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    for (label, token) in fixture["rejected"].as_object().unwrap() {
        let mut stored = fixture["storedTokens"].clone();
        stored["accessToken"] = token.clone();
        let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
        let storage = MemoryTokenStorage::with_value(&stored.to_string());
        let clock = move || now;
        let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();
        assert!(client.existing_session().is_err(), "{label} was accepted");
        // A credential that cannot be verified is dropped, not kept around.
        assert!(storage.read().unwrap().is_none(), "{label} was left on disk");
    }
}

#[test]
fn a_valid_stored_session_needs_no_token_call() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let session = client.existing_session().unwrap().unwrap();
    assert_eq!(session.user.sub, fixture["subject"].as_str().unwrap());
    assert_eq!(http.count(&format!("{issuer}/oauth/token")), 0);
}

/// ID-17: an unknown `kid` refetches once, then the cooldown holds.
#[test]
fn an_unknown_kid_refetches_the_jwks_at_most_once() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let mut stored = fixture["storedTokens"].clone();
    stored["accessToken"] = fixture["rejected"]["unknownKid"].clone();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&stored.to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    assert!(client.existing_session().is_err());
    let after_first = http.count(&format!("{issuer}/.well-known/jwks.json"));
    assert_eq!(after_first, 2, "the first unknown kid should refetch exactly once");

    let storage = MemoryTokenStorage::with_value(&stored.to_string());
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();
    let _ = client.existing_session();
    // A fresh client fetches its own initial copy; what matters is that the
    // cooldown stopped the *same* client from looping, which the count above
    // pins.
    assert!(http.count(&format!("{issuer}/.well-known/jwks.json")) <= 4);
}

// -- ID-21: configuration drift -------------------------------------------

#[test]
fn a_credential_for_another_issuer_is_discarded() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let mut stored = fixture["storedTokens"].clone();
    stored["issuer"] = json!("https://api.somewhere-else.test");
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&stored.to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    assert!(client.existing_session().unwrap().is_none());
    assert!(storage.read().unwrap().is_none());
}

// -- ID-23, ID-24, ID-25: refresh -----------------------------------------

#[test]
fn refresh_happens_five_minutes_before_expiry_and_rotates() {
    let fixture = fixture("oidc.json");
    let expiry = fixture["accessExpiresAtEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    // Four minutes before expiry: inside the five-minute window.
    let now = expiry - 4 * 60 * 1_000;
    let http = provider(fixture.clone(), fixture["refreshedTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let session = client.existing_session().unwrap().unwrap();
    assert_eq!(session.user.sub, fixture["subject"].as_str().unwrap());

    let form = http.last_form(&format!("{issuer}/oauth/token"));
    assert_eq!(form_value(&form, "grant_type").unwrap(), "refresh_token");
    assert_eq!(form_value(&form, "refresh_token").unwrap(), "refresh-token-1");
    assert_eq!(form_value(&form, "client_id").unwrap(), "svartal-cli");
    let stored = StoredTokens::parse(&storage.read().unwrap().unwrap()).unwrap();
    assert_eq!(stored.refresh_token, "refresh-token-2");
}

#[test]
fn a_refresh_token_that_is_not_rotated_ends_the_session() {
    let fixture = fixture("oidc.json");
    let expiry = fixture["accessExpiresAtEpochMs"].as_i64().unwrap();
    let now = expiry - 4 * 60 * 1_000;
    let mut response = fixture["refreshedTokenResponse"].clone();
    response["refresh_token"] = json!("refresh-token-1");
    let http = provider(fixture.clone(), response);
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let error = client.existing_session().unwrap_err();
    assert_eq!(error.recovery, Recovery::SignIn);
    assert!(storage.read().unwrap().is_none());
}

#[test]
fn a_refresh_that_changes_the_subject_ends_the_session() {
    let fixture = fixture("oidc.json");
    let expiry = fixture["accessExpiresAtEpochMs"].as_i64().unwrap();
    let now = expiry - 4 * 60 * 1_000;
    let http = provider(fixture.clone(), fixture["subjectChangedTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let error = client.existing_session().unwrap_err();
    assert_eq!(error.recovery, Recovery::SignIn);
    assert!(error.message.contains("subject changed"));
    assert!(storage.read().unwrap().is_none());
}

/// ID-26: a 5xx on a refresh is transient; a 400 is terminal.
#[test]
fn the_recovery_hint_separates_transient_from_terminal() {
    let fixture = fixture("oidc.json");
    let expiry = fixture["accessExpiresAtEpochMs"].as_i64().unwrap();
    let now = expiry - 4 * 60 * 1_000;
    for (status, body, expected) in [
        (503u16, json!({}), Recovery::Retry),
        (429, json!({}), Recovery::Retry),
        (400, json!({ "error": "invalid_grant" }), Recovery::SignIn),
        (401, json!({ "error": "invalid_client" }), Recovery::SignIn),
    ] {
        let issuer = fixture["issuer"].as_str().unwrap().to_string();
        let fixture_for_router = fixture.clone();
        let http = FakeTransport::new(move |request| {
            let url = request.url.as_str();
            if url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &fixture_for_router["discovery"]);
            }
            if url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &fixture_for_router["jwks"]);
            }
            json_response(status, &body)
        });
        let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
        let clock = move || now;
        let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();
        let error = client.existing_session().unwrap_err();
        assert_eq!(error.recovery, expected, "HTTP {status}");
    }
}

// -- ID-9: discovery -------------------------------------------------------

#[test]
fn discovery_endpoints_must_stay_on_the_issuer_origin() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    for (label, document) in [
        (
            "another origin",
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/oauth/authorize"),
                "token_endpoint": "https://tokens.evil.test/oauth/token",
                "revocation_endpoint": format!("{issuer}/oauth/revoke"),
                "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            }),
        ),
        (
            "plain http",
            json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/oauth/authorize"),
                "token_endpoint": format!("{issuer}/oauth/token"),
                "revocation_endpoint": format!("{issuer}/oauth/revoke"),
                "jwks_uri": "http://api.example.test/.well-known/jwks.json",
            }),
        ),
        (
            "a different issuer",
            json!({
                "issuer": "https://api.somewhere-else.test",
                "authorization_endpoint": format!("{issuer}/oauth/authorize"),
                "token_endpoint": format!("{issuer}/oauth/token"),
                "revocation_endpoint": format!("{issuer}/oauth/revoke"),
                "jwks_uri": format!("{issuer}/.well-known/jwks.json"),
            }),
        ),
    ] {
        let http = FakeTransport::new(move |_| json_response(200, &document));
        let storage = MemoryTokenStorage::new();
        let clock = move || now;
        let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();
        assert!(client.begin_authorization().is_err(), "{label} was accepted");
    }
}

// -- ID-27: sign-out -------------------------------------------------------

#[test]
fn sign_out_clears_first_then_revokes() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    assert!(client.sign_out().unwrap());
    assert!(storage.read().unwrap().is_none());
    let form = http.last_form(&format!("{issuer}/oauth/revoke"));
    assert_eq!(form_value(&form, "token").unwrap(), "refresh-token-1");
    assert_eq!(form_value(&form, "token_type_hint").unwrap(), "refresh_token");
    assert_eq!(form_value(&form, "client_id").unwrap(), "svartal-cli");
}

#[test]
fn signing_out_with_nothing_stored_says_so_without_calling_anywhere() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let http = provider(fixture.clone(), fixture["initialTokenResponse"].clone());
    let storage = MemoryTokenStorage::new();
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    assert!(!client.sign_out().unwrap());
    assert!(http.urls().is_empty());
}

/// A failed revocation still leaves the local session gone (ID-27).
#[test]
fn a_failed_revocation_still_removes_the_local_credential() {
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let fixture_for_router = fixture.clone();
    let http = FakeTransport::new(move |request| {
        if request.url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture_for_router["discovery"]);
        }
        json_response(500, &json!({}))
    });
    let storage = MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string());
    let clock = move || now;
    let mut client = OidcClient::new(oidc_config(&fixture), &http, &storage, &clock).unwrap();

    let error = client.sign_out().unwrap_err();
    assert!(error.message.contains("could not be revoked"));
    assert!(storage.read().unwrap().is_none());
}
