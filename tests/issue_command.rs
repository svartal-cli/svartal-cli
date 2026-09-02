//! `sv issue post|link|unlink|transcript`, and the API token underneath them.
//!
//! The OIDC access token opens only `/api/v1/client/*`, so the first `sv
//! issue` mints a durable API token there and every project call after that
//! carries the minted secret. What these tests pin: the mint happens once and
//! lands in a `0600` file, a refused secret is minted again and the call
//! retried exactly once, an expired file is replaced before it is sent, the
//! request bodies say what the plan says they say, and `sv logout` revokes
//! the token and removes the file.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Mutex;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::browser::NoBrowser;
use svartal::commands::{self, Context};
use svartal::config::resolve_config;
use svartal::http::{Body, Request};
use svartal::store::{ApiTokenFile, MemoryTokenStorage, StoredApiToken, rfc3339_to_epoch_ms};

const WEB_URL: &str = "https://web.example.test";
const PROJECT: &str = "marc/demo";
const PROJECT_ID: &str = "proj-1";
const WORK_ITEM_ID: &str = "wi-1";
const TRANSCRIPT_ID: &str = "tr-1";
const STALE_SECRET: &str = "kh_secret_stale";
/// Well after the fixture's `nowEpochMs` (2026-07-30).
const FRESH_EXPIRY: &str = "2026-12-01T00:00:00Z";

fn bearer(request: &Request) -> Option<String> {
    request
        .headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .and_then(|(_, value)| value.strip_prefix("Bearer ").map(str::to_string))
}

fn json_body(request: &Request) -> Value {
    match &request.body {
        Some(Body::Json(value)) => value.clone(),
        _ => Value::Null,
    }
}

/// Svartal: the identity endpoints from the fixture, the client token mint,
/// and the project routes. Every secret it minted is accepted; `STALE_SECRET`
/// and anything else is refused with 401. Transcripts dedupe on the second
/// post.
fn transport(fixture: Value) -> FakeTransport {
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let oidc_access_token = fixture["storedTokens"]["accessToken"]
        .as_str()
        .unwrap()
        .to_string();
    let minted = Mutex::new(0usize);
    let transcripts = Mutex::new(0usize);
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &fixture["jwks"]);
        }
        if url
            == fixture["discovery"]["revocation_endpoint"]
                .as_str()
                .unwrap()
        {
            return json_response(200, &json!({}));
        }
        if url == format!("{issuer}/api/v1/client/tokens") && request.method == "POST" {
            if bearer(request).as_deref() != Some(oidc_access_token.as_str()) {
                return json_response(
                    401,
                    &json!({ "errors": { "detail": "Authentication required" } }),
                );
            }
            let mut count = minted.lock().unwrap();
            *count += 1;
            let body = json_body(request);
            return json_response(
                201,
                &json!({ "data": {
                    "id": format!("tok-{}", *count),
                    "name": body["name"],
                    "scopes": body["scopes"],
                    "secret": format!("kh_secret_{}", *count),
                    "expiresAt": FRESH_EXPIRY,
                }}),
            );
        }
        let Some(path) = url.strip_prefix(&format!("{issuer}/api/v1/")) else {
            return json_response(404, &json!({ "errors": { "detail": "unexpected url" } }));
        };
        if path.starts_with("tokens/") && request.method == "DELETE" {
            return json_response(
                200,
                &json!({ "data": { "id": "tok-1", "revokedAt": FRESH_EXPIRY } }),
            );
        }
        let accepted = bearer(request)
            .is_some_and(|secret| secret.starts_with("kh_secret_") && secret != STALE_SECRET);
        if !accepted {
            return json_response(
                401,
                &json!({ "errors": { "detail": "Authentication required" } }),
            );
        }
        match (request.method, path) {
            ("POST", "projects/marc%2Fdemo/work-items") => {
                let body = json_body(request);
                if body["title"].as_str().unwrap_or_default().is_empty() {
                    return json_response(
                        422,
                        &json!({ "errors": { "title": ["can't be blank"] } }),
                    );
                }
                json_response(
                    201,
                    &json!({ "data": { "id": WORK_ITEM_ID, "number": 12, "projectId": PROJECT_ID, "kind": body["kind"] } }),
                )
            }
            ("GET", "projects/marc%2Fdemo/work-items?number=12") => json_response(
                200,
                &json!({ "data": [{ "id": WORK_ITEM_ID, "number": 12, "projectId": PROJECT_ID }] }),
            ),
            ("GET", path) if path.starts_with("projects/marc%2Fdemo/work-items?number=") => {
                json_response(200, &json!({ "data": [] }))
            }
            ("POST", "work-items/wi-1/bundles/feature-a") => json_response(
                201,
                &json!({ "data": { "bundleId": "b-1", "workItemId": WORK_ITEM_ID } }),
            ),
            ("DELETE", "work-items/wi-1/bundles/feature-a") => svartal::http::Response {
                status: 204,
                body: Vec::new(),
            },
            ("POST", "projects/marc%2Fdemo/transcripts") => {
                let mut count = transcripts.lock().unwrap();
                *count += 1;
                let status = if *count == 1 { 201 } else { 200 };
                json_response(
                    status,
                    &json!({ "data": { "id": TRANSCRIPT_ID, "projectId": PROJECT_ID } }),
                )
            }
            _ => json_response(404, &json!({ "errors": { "detail": "Not found" } })),
        }
    })
}

struct Harness {
    dir: TempDir,
    http: FakeTransport,
    storage: MemoryTokenStorage,
    fixture: Value,
}

impl Harness {
    fn new(tag: &str, signed_in: bool) -> Self {
        let fixture = fixture("oidc.json");
        let http = transport(fixture.clone());
        let storage = if signed_in {
            MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string())
        } else {
            MemoryTokenStorage::new()
        };
        Self {
            dir: TempDir::new(tag),
            http,
            storage,
            fixture,
        }
    }

    fn config_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("config")
    }

    fn token_file(&self) -> ApiTokenFile {
        ApiTokenFile::new(&self.config_dir())
    }

    /// Every command runs with `SVARTAL_CONFIG_DIR` inside the temporary
    /// directory, so nothing here can touch `~/.config/svartal`.
    fn run<F>(&self, command: F) -> (Result<(), commands::CliError>, String)
    where
        F: FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), commands::CliError>,
    {
        let now = self.fixture["nowEpochMs"].as_i64().unwrap();
        let environment = [
            (
                "HOME".to_string(),
                self.dir.path().to_string_lossy().to_string(),
            ),
            (
                "SVARTAL_CONFIG_DIR".to_string(),
                self.config_dir().to_string_lossy().to_string(),
            ),
            (
                "SVARTAL_ISSUER".to_string(),
                self.fixture["issuer"].as_str().unwrap().to_string(),
            ),
            (
                "SVARTAL_RELAY_URL".to_string(),
                self.fixture["relayUrl"].as_str().unwrap().to_string(),
            ),
            ("SVARTAL_WEB_URL".to_string(), WEB_URL.to_string()),
        ]
        .into_iter()
        .collect();
        let clock = move || now;
        let browser = NoBrowser;
        let context = Context {
            config: resolve_config(&environment).unwrap(),
            http: &self.http,
            storage: &self.storage,
            browser: &browser,
            now: &clock,
        };
        let mut out: Vec<u8> = Vec::new();
        let outcome = command(&context, &mut out);
        (outcome, String::from_utf8(out).unwrap())
    }

    fn mint_url(&self) -> String {
        format!(
            "{}/api/v1/client/tokens",
            self.fixture["issuer"].as_str().unwrap()
        )
    }

    fn api_url(&self, path: &str) -> String {
        format!("{}/api/v1/{path}", self.fixture["issuer"].as_str().unwrap())
    }

    fn requests_to(&self, url: &str) -> Vec<Request> {
        self.http
            .requests()
            .into_iter()
            .filter(|request| request.url == url)
            .collect()
    }

    fn stored_secret(&self) -> Option<String> {
        self.token_file().read().unwrap().map(|token| token.secret)
    }
}

fn post(
    bundles: &[String],
) -> impl Fn(&Context<'_>, &mut dyn std::io::Write) -> Result<(), commands::CliError> + '_ {
    move |context, out| {
        commands::issue_post(
            context,
            out,
            &commands::IssuePost {
                project: PROJECT,
                kind: "issue",
                title: "Retry the relay handshake",
                body: Some("The handshake drops once a day.\n"),
                bundles,
                agent: Some("claude-code"),
                thread: Some("thread-9"),
                json: false,
            },
        )
    }
}

fn write_transcript(dir: &Path) -> std::path::PathBuf {
    let path = dir.join("transcript.json");
    std::fs::write(
        &path,
        json!({
            "format": "ivaldi-transcript/v1",
            "threadId": "thread-9",
            "title": "Retry the relay handshake",
            "turns": [{ "turnId": "t1", "messages": [{ "role": "user", "text": "hi" }] }],
        })
        .to_string(),
    )
    .unwrap();
    path
}

// -- the API token ---------------------------------------------------------

#[test]
fn the_first_post_mints_an_api_token_once_and_keeps_it_in_a_private_file() {
    let harness = Harness::new("issue-post", true);
    let bundles = vec!["feature-a".to_string()];
    let (outcome, output) = harness.run(post(&bundles));
    outcome.unwrap();
    assert_eq!(
        output,
        format!("#12 {WEB_URL}/app/projects/{PROJECT_ID}/issues/12\n")
    );

    // One mint, with the OIDC bearer, asking for exactly the project scopes.
    let mints = harness.requests_to(&harness.mint_url());
    assert_eq!(mints.len(), 1);
    let mint = json_body(&mints[0]);
    assert!(
        mint["name"].as_str().unwrap().starts_with("sv on "),
        "{mint}"
    );
    assert_eq!(mint["scopes"], json!(["project:read", "project:write"]));
    assert_eq!(mint["expiresInDays"], 90);

    // The token file: private, and the secret Svartal answered with.
    let file = harness.token_file();
    let mode = std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    let stored = file.read().unwrap().unwrap();
    assert_eq!(
        stored,
        StoredApiToken {
            version: 1,
            id: "tok-1".to_string(),
            secret: "kh_secret_1".to_string(),
            expires_at: Some(FRESH_EXPIRY.to_string()),
        }
    );

    // The post itself: the minted secret, the project as one path segment,
    // and the body the plan describes — `issue` is Svartal's `feature`.
    let posts = harness.requests_to(&harness.api_url("projects/marc%2Fdemo/work-items"));
    assert_eq!(posts.len(), 1);
    assert_eq!(bearer(&posts[0]).as_deref(), Some("kh_secret_1"));
    let body = json_body(&posts[0]);
    assert_eq!(body["title"], "Retry the relay handshake");
    assert_eq!(body["kind"], "feature");
    assert_eq!(body["description"], "The handshake drops once a day.");
    assert_eq!(body["bundles"], json!(["feature-a"]));
    assert_eq!(body["postedVia"]["client"], "sv");
    assert_eq!(body["postedVia"]["agent"], "claude-code");
    assert_eq!(body["postedVia"]["threadId"], "thread-9");
    assert_eq!(
        body["postedVia"]["note"],
        "Posted by claude-code via the sv CLI"
    );
    assert!(body["postedVia"]["machine"].is_string(), "{body}");
    assert!(
        body.get("authorUserId").is_none(),
        "the author is never named by the client"
    );

    // A second command finds the file and does not mint again.
    let (outcome, _) = harness.run(post(&[]));
    outcome.unwrap();
    assert_eq!(harness.requests_to(&harness.mint_url()).len(), 1);
    let second = harness.requests_to(&harness.api_url("projects/marc%2Fdemo/work-items"));
    assert_eq!(second.len(), 2);
    assert!(
        json_body(&second[1]).get("bundles").is_none(),
        "no bundles, no field"
    );
}

#[test]
fn a_refused_secret_is_minted_again_and_the_request_sent_once_more() {
    let harness = Harness::new("issue-401", true);
    harness
        .token_file()
        .write(&StoredApiToken {
            version: 1,
            id: "tok-stale".to_string(),
            secret: STALE_SECRET.to_string(),
            expires_at: Some(FRESH_EXPIRY.to_string()),
        })
        .unwrap();

    let (outcome, output) = harness.run(post(&[]));
    outcome.unwrap();
    assert!(output.starts_with("#12 "), "{output}");

    let posts = harness.requests_to(&harness.api_url("projects/marc%2Fdemo/work-items"));
    assert_eq!(posts.len(), 2, "one refusal, one retry, nothing more");
    assert_eq!(bearer(&posts[0]).as_deref(), Some(STALE_SECRET));
    assert_eq!(bearer(&posts[1]).as_deref(), Some("kh_secret_1"));
    assert_eq!(harness.requests_to(&harness.mint_url()).len(), 1);
    assert_eq!(harness.stored_secret().as_deref(), Some("kh_secret_1"));
}

#[test]
fn an_expired_token_is_replaced_before_anything_is_sent() {
    let harness = Harness::new("issue-expired", true);
    harness
        .token_file()
        .write(&StoredApiToken {
            version: 1,
            id: "tok-old".to_string(),
            secret: "kh_secret_old".to_string(),
            expires_at: Some("2026-01-01T00:00:00Z".to_string()),
        })
        .unwrap();

    let (outcome, _) = harness.run(post(&[]));
    outcome.unwrap();
    let posts = harness.requests_to(&harness.api_url("projects/marc%2Fdemo/work-items"));
    assert_eq!(posts.len(), 1);
    assert_eq!(bearer(&posts[0]).as_deref(), Some("kh_secret_1"));
    assert_eq!(harness.requests_to(&harness.mint_url()).len(), 1);
}

#[test]
fn without_a_session_nothing_is_minted() {
    let harness = Harness::new("issue-signed-out", false);
    let (outcome, _) = harness.run(post(&[]));
    assert_eq!(outcome.unwrap_err().to_string(), commands::NOT_SIGNED_IN);
    assert!(harness.requests_to(&harness.mint_url()).is_empty());
    assert!(harness.token_file().read().unwrap().is_none());
}

#[test]
fn a_rejected_post_says_what_svartal_said() {
    let harness = Harness::new("issue-422", true);
    let (outcome, _) = harness.run(|context, out| {
        commands::issue_post(
            context,
            out,
            &commands::IssuePost {
                project: PROJECT,
                kind: "epic",
                title: "x",
                body: None,
                bundles: &[],
                agent: None,
                thread: None,
                json: false,
            },
        )
    });
    let message = outcome.unwrap_err().to_string();
    assert!(
        message.contains("`epic` is not a kind of issue"),
        "{message}"
    );
    assert!(
        harness.http.requests().is_empty(),
        "a bad kind never reaches the network"
    );
}

// -- link / unlink ----------------------------------------------------------

#[test]
fn link_and_unlink_resolve_the_number_and_call_the_bundle_route() {
    let harness = Harness::new("issue-link", true);
    let (outcome, output) = harness
        .run(|context, out| commands::issue_link(context, out, PROJECT, "#12", "feature-a", false));
    outcome.unwrap();
    assert_eq!(output, "Linked bundle feature-a to #12.\n");
    assert_eq!(
        harness
            .requests_to(&harness.api_url("projects/marc%2Fdemo/work-items?number=12"))
            .len(),
        1
    );
    let linked = harness.requests_to(&harness.api_url("work-items/wi-1/bundles/feature-a"));
    assert_eq!(linked.len(), 1);
    assert_eq!(linked[0].method, "POST");
    assert!(linked[0].body.is_none());

    let (outcome, output) = harness
        .run(|context, out| commands::issue_link(context, out, PROJECT, "12", "feature-a", true));
    outcome.unwrap();
    assert_eq!(output, "Unlinked bundle feature-a from #12.\n");
    let calls = harness.requests_to(&harness.api_url("work-items/wi-1/bundles/feature-a"));
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1].method, "DELETE");

    let (outcome, _) = harness
        .run(|context, out| commands::issue_link(context, out, PROJECT, "#99", "feature-a", false));
    assert_eq!(
        outcome.unwrap_err().to_string(),
        "Project marc/demo has no issue #99."
    );
}

// -- transcript -------------------------------------------------------------

#[test]
fn transcript_posts_the_document_whole_and_reports_a_duplicate() {
    let harness = Harness::new("issue-transcript", true);
    let path = write_transcript(harness.dir.path());
    let bundles = vec!["feature-a".to_string()];
    let transcript = |json: bool| commands::IssueTranscript {
        project: PROJECT,
        file: &path,
        work_item: Some("#12"),
        bundles: &bundles,
        title: None,
        agent: Some("claude-code"),
        thread: None,
        json,
    };

    let (outcome, output) =
        harness.run(|context, out| commands::issue_transcript(context, out, &transcript(false)));
    outcome.unwrap();
    assert_eq!(
        output,
        format!(
            "Saved transcript {WEB_URL}/app/projects/{PROJECT_ID}/transcripts/{TRANSCRIPT_ID}\n"
        )
    );

    let posts = harness.requests_to(&harness.api_url("projects/marc%2Fdemo/transcripts"));
    assert_eq!(posts.len(), 1);
    let body = json_body(&posts[0]);
    assert_eq!(
        body["title"], "Retry the relay handshake",
        "the document's title"
    );
    assert_eq!(body["source"], "sv");
    assert_eq!(body["threadId"], "thread-9", "the document's thread");
    assert_eq!(body["format"], "summary");
    assert_eq!(body["workItemId"], WORK_ITEM_ID);
    assert_eq!(body["bundles"], json!(["feature-a"]));
    assert_eq!(body["transcript"]["format"], "ivaldi-transcript/v1");
    assert_eq!(body["transcript"]["turns"].as_array().unwrap().len(), 1);
    assert_eq!(
        body["postedVia"]["note"],
        "Posted by claude-code via the sv CLI"
    );

    // Same content again: Svartal answers 200 with the record it already had.
    let (outcome, output) =
        harness.run(|context, out| commands::issue_transcript(context, out, &transcript(true)));
    outcome.unwrap();
    let reported: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(reported["id"], TRANSCRIPT_ID);
    assert_eq!(reported["duplicate"], true);
    assert_eq!(reported["workItemId"], WORK_ITEM_ID);
}

#[test]
fn a_transcript_without_a_title_asks_for_one() {
    let harness = Harness::new("issue-transcript-title", true);
    let path = harness.dir.path().join("untitled.json");
    std::fs::write(
        &path,
        json!({ "format": "ivaldi-transcript/v1", "turns": [] }).to_string(),
    )
    .unwrap();
    let (outcome, _) = harness.run(|context, out| {
        commands::issue_transcript(
            context,
            out,
            &commands::IssueTranscript {
                project: PROJECT,
                file: &path,
                work_item: None,
                bundles: &[],
                title: None,
                agent: None,
                thread: None,
                json: false,
            },
        )
    });
    assert_eq!(
        outcome.unwrap_err().to_string(),
        "The transcript has no title. Pass `--title <title>`."
    );
    assert!(
        harness
            .requests_to(&harness.api_url("projects/marc%2Fdemo/transcripts"))
            .is_empty()
    );
}

// -- logout -----------------------------------------------------------------

#[test]
fn logout_revokes_the_api_token_and_removes_its_file() {
    let harness = Harness::new("issue-logout", true);
    harness
        .token_file()
        .write(&StoredApiToken {
            version: 1,
            id: "tok-1".to_string(),
            secret: "kh_secret_1".to_string(),
            expires_at: Some(FRESH_EXPIRY.to_string()),
        })
        .unwrap();
    let (outcome, output) = harness.run(|context, out| commands::logout(context, out));
    outcome.unwrap();
    assert!(
        output.contains("The Svartal API token was revoked."),
        "{output}"
    );
    assert!(output.contains("Signed out."), "{output}");
    let revocations = harness.requests_to(&harness.api_url("tokens/tok-1"));
    assert_eq!(revocations.len(), 1);
    assert_eq!(revocations[0].method, "DELETE");
    assert_eq!(bearer(&revocations[0]).as_deref(), Some("kh_secret_1"));
    assert!(!harness.token_file().path().exists());
}

// -- the expiry parser ------------------------------------------------------

#[test]
fn svartal_timestamps_become_epoch_milliseconds() {
    assert_eq!(
        rfc3339_to_epoch_ms("2026-07-30T12:00:00Z"),
        Some(1_785_412_800_000)
    );
    assert_eq!(
        rfc3339_to_epoch_ms("2026-07-30T12:00:00.250Z"),
        Some(1_785_412_800_250)
    );
    assert_eq!(
        rfc3339_to_epoch_ms("2026-07-30T14:00:00+02:00"),
        Some(1_785_412_800_000)
    );
    assert_eq!(rfc3339_to_epoch_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(rfc3339_to_epoch_ms("next week"), None);
    assert_eq!(rfc3339_to_epoch_ms("2026-07-30T12:00:00"), None);
}
