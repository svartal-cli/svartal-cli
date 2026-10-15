//! Project visibility uses fake HTTP only, including token minting.
mod common;

use std::collections::VecDeque;
use std::sync::Mutex;

use common::{FakeTransport, TempDir, fixture, json_response};
use serde_json::{Value, json};
use svartal::browser::NoBrowser;
use svartal::commands::{CliError, Context};
use svartal::config::resolve_config;
use svartal::http::{Body, Request, Response};
use svartal::store::{ApiTokenFile, MemoryTokenStorage, StoredApiToken};

const ID: &str = "11111111-1111-4111-8111-111111111111";

fn project(id: &str, owner: &str, visibility: &str) -> Value {
    json!({"id": id, "slug": "demo", "owner": {"slug": owner}, "visibility": visibility})
}

fn reply(data: Value) -> Response {
    json_response(200, &json!({"data": data}))
}

type ExpectedCalls = std::sync::Arc<Mutex<VecDeque<(&'static str, String, Response)>>>;

struct Harness {
    dir: TempDir,
    fixture: Value,
    storage: MemoryTokenStorage,
    http: FakeTransport,
    remaining: ExpectedCalls,
}

impl Harness {
    fn new(signed_in: bool, calls: Vec<(&'static str, String, Response)>) -> Self {
        let fixture = fixture("oidc.json");
        let f = fixture.clone();
        let remaining = std::sync::Arc::new(Mutex::new(VecDeque::from(calls)));
        let pending = remaining.clone();
        let http = FakeTransport::new(move |request| {
            let issuer = f["issuer"].as_str().unwrap();
            if request.url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &f["discovery"]);
            }
            if request.url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &f["jwks"]);
            }
            if request.url == format!("{issuer}/api/v1/client/tokens") {
                assert_eq!(request.method, "POST");
                assert_eq!(
                    body(request)["scopes"],
                    json!(["project:read", "project:write"])
                );
                assert!(request.headers.contains(&(
                    "authorization".into(),
                    format!(
                        "Bearer {}",
                        f["storedTokens"]["accessToken"].as_str().unwrap()
                    )
                )));
                return json_response(
                    201,
                    &json!({"data": {
                        "id": "token-1", "secret": "secret", "expiresAt": "2026-12-01T00:00:00Z"
                    }}),
                );
            }
            let (method, path, response) =
                pending.lock().unwrap().pop_front().unwrap_or_else(|| {
                    panic!("Unexpected request: {} {}", request.method, request.url)
                });
            assert_eq!(request.method, method);
            assert_eq!(request.url, format!("{issuer}/api/v1{path}"));
            assert!(
                request
                    .headers
                    .contains(&("authorization".into(), "Bearer secret".into()))
            );
            response
        });
        Self {
            dir: TempDir::new("project-visibility"),
            storage: if signed_in {
                MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string())
            } else {
                MemoryTokenStorage::new()
            },
            fixture,
            http,
            remaining,
        }
    }

    fn run(&self, project: &str, value: Option<&str>) -> (Result<(), CliError>, String) {
        self.with_context(|context, out| svartal::project::visibility(context, out, project, value))
    }

    fn with_context(
        &self,
        command: impl FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), CliError>,
    ) -> (Result<(), CliError>, String) {
        let environment = [
            (
                "HOME".into(),
                self.dir.path().to_string_lossy().into_owned(),
            ),
            (
                "SVARTAL_CONFIG_DIR".into(),
                self.dir.path().to_string_lossy().into_owned(),
            ),
            (
                "SVARTAL_ISSUER".into(),
                self.fixture["issuer"].as_str().unwrap().into(),
            ),
            (
                "SVARTAL_RELAY_URL".into(),
                self.fixture["relayUrl"].as_str().unwrap().into(),
            ),
            ("SVARTAL_WEB_URL".into(), "https://web.example.test".into()),
        ]
        .into_iter()
        .collect();
        let clock = || self.fixture["nowEpochMs"].as_i64().unwrap();
        let context = Context {
            config: resolve_config(&environment).unwrap(),
            http: &self.http,
            storage: &self.storage,
            browser: &NoBrowser,
            now: &clock,
        };
        let mut out = Vec::new();
        let result = command(&context, &mut out);
        assert!(
            self.remaining.lock().unwrap().is_empty(),
            "expected calls missing"
        );
        (result, String::from_utf8(out).unwrap())
    }
}

fn body(request: &Request) -> Value {
    match &request.body {
        Some(Body::Json(value)) => value.clone(),
        _ => Value::Null,
    }
}

fn get(path: &str, data: Value) -> (&'static str, String, Response) {
    ("GET", path.into(), reply(data))
}

#[test]
fn show_slug_and_uuid_read_without_writing_including_internal() {
    for name in ["demo", ID] {
        for visibility in ["public", "private", "internal"] {
            let h = Harness::new(
                true,
                vec![get(
                    &format!("/projects/{name}"),
                    project(ID, "alice", visibility),
                )],
            );
            let (result, out) = h.run(name, None);
            result.unwrap();
            assert_eq!(
                out,
                format!("{name}: {visibility}\nhttps://web.example.test/app/projects/{ID}\n")
            );
            assert!(h.http.requests().iter().all(|r| r.method != "PATCH"));
        }
    }
}

#[test]
fn public_and_private_patch_only_visibility() {
    for value in ["public", "private"] {
        let h = Harness::new(
            true,
            vec![(
                "PATCH",
                "/projects/demo".to_string(),
                reply(project(ID, "alice", value)),
            )],
        );
        let (result, out) = h.run("demo", Some(value));
        result.unwrap();
        assert_eq!(
            out,
            format!("demo: now {value}\nhttps://web.example.test/app/projects/{ID}\n")
        );
        let requests = h.http.requests();
        let patch = requests.iter().find(|r| r.method == "PATCH").unwrap();
        assert_eq!(body(patch), json!({"visibility": value}));
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.url.ends_with("/client/tokens"))
                .count(),
            1
        );
    }
}

#[test]
fn http_statuses_are_mapped_without_inspecting_error_text() {
    for method in ["GET", "PATCH"] {
        for (status, message) in [
            (403, "Only the project's owner can change its visibility."),
            (404, "No project named demo."),
        ] {
            let calls = vec![(
                method,
                "/projects/demo".to_string(),
                Response {
                    status,
                    body: b"not JSON".to_vec(),
                },
            )];
            let h = Harness::new(true, calls);
            let value = (method == "PATCH").then_some("public");
            let (result, out) = h.run("demo", value);
            assert_eq!(result.unwrap_err().to_string(), message);
            assert!(out.is_empty());
            assert_eq!(
                h.http
                    .requests()
                    .iter()
                    .filter(|r| r.url.ends_with("/client/tokens"))
                    .count(),
                1
            );
        }
    }
}

#[test]
fn signed_out_does_not_call_the_api() {
    let h = Harness::new(false, vec![]);
    let (result, _) = h.run("demo", None);
    assert_eq!(
        result.unwrap_err().to_string(),
        svartal::commands::NOT_SIGNED_IN
    );
    assert!(h.http.requests().is_empty());
}

#[test]
fn other_http_errors_preserve_server_detail() {
    let h = Harness::new(
        true,
        vec![(
            "GET",
            "/projects/demo".into(),
            json_response(
                409,
                &json!({"errors": {"detail": "Ambiguous project; use owner/slug"}}),
            ),
        )],
    );
    let message = h.run("demo", None).0.unwrap_err().to_string();
    assert!(message.contains("Ambiguous project; use owner/slug"));
    assert!(message.contains("HTTP 409"));
}

#[test]
fn legacy_api_request_keeps_403_login_message() {
    let h = Harness::new(
        true,
        vec![(
            "GET",
            "/projects/demo".into(),
            json_response(403, &json!({})),
        )],
    );
    let (result, _) = h.with_context(|context, _| {
        svartal::api::api_request(context, "GET", "/projects/demo", None, "read the project")
            .map(|_| ())
    });
    assert_eq!(
        result.unwrap_err().to_string(),
        "Svartal refused the request to read the project. Run `sv login` and try again."
    );
}

#[test]
fn persistent_401_retries_only_once_and_asks_for_login() {
    let h = Harness::new(
        true,
        vec![
            (
                "GET",
                "/projects/demo".into(),
                json_response(401, &json!({})),
            ),
            (
                "GET",
                "/projects/demo".into(),
                json_response(401, &json!({})),
            ),
        ],
    );
    ApiTokenFile::new(h.dir.path())
        .write(&StoredApiToken {
            version: 1,
            id: "token-old".into(),
            secret: "secret".into(),
            expires_at: Some("2026-12-01T00:00:00Z".into()),
        })
        .unwrap();
    let (result, out) = h.run("demo", None);
    assert!(result.unwrap_err().to_string().contains("sv login"));
    assert!(out.is_empty());
    assert_eq!(
        h.http
            .requests()
            .iter()
            .filter(|r| r.url.ends_with("/client/tokens"))
            .count(),
        1
    );
}

#[test]
fn parser_enforces_verb_arity_and_values() {
    use svartal::project::parse_visibility_args as parse;
    assert_eq!(
        parse(&["visibility", "alice/demo"]).unwrap(),
        ("alice/demo", None)
    );
    assert_eq!(
        parse(&["visibility", ID, "public"]).unwrap(),
        (ID, Some("public"))
    );
    for args in [
        vec![],
        vec!["visibility"],
        vec!["other", "demo"],
        vec!["visibility", "demo", "public", "extra"],
        vec!["visibility", ""],
    ] {
        assert!(parse(&args).unwrap_err().contains("Usage:"));
    }
    assert!(
        parse(&["visibility", "demo", "internal"])
            .unwrap_err()
            .contains("public, private")
    );
}

#[test]
fn binary_wires_parser_and_help_without_network() {
    for args in [
        vec!["project"],
        vec!["project", "visibility"],
        vec!["project", "visibility", "demo", "public", "extra"],
        vec!["project", "visibility", "demo", "wrong"],
        vec!["project", "visibility", "demo", "--json"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
            .env_clear()
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let err = String::from_utf8(output.stderr).unwrap();
        assert!(
            err.contains("Usage:")
                || err.contains("public, private")
                || err.contains("not an option"),
            "{err}"
        );
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
        .env_clear()
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("project visibility <project> [public|private]")
    );
}

#[test]
fn patch_401_retries_the_identical_write_with_a_fresh_token() {
    let h = Harness::new(
        true,
        vec![
            (
                "PATCH",
                "/projects/demo".to_string(),
                json_response(401, &json!({})),
            ),
            (
                "PATCH",
                "/projects/demo".to_string(),
                reply(project(ID, "alice", "public")),
            ),
        ],
    );
    h.run("demo", Some("public")).0.unwrap();
    let requests = h.http.requests();
    let patches: Vec<_> = requests.iter().filter(|r| r.method == "PATCH").collect();
    assert_eq!(patches.len(), 2);
    assert_eq!(body(patches[0]), json!({"visibility": "public"}));
    assert_eq!(body(patches[0]), body(patches[1]));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.url.ends_with("/client/tokens"))
            .count(),
        2
    );
}

#[test]
fn identifier_is_encoded_as_data_not_url_syntax() {
    let h = Harness::new(
        true,
        vec![(
            "GET",
            "/projects/demo%3Fowner%3Dbob%23fragment".into(),
            json_response(404, &json!({})),
        )],
    );
    assert_eq!(
        h.run("demo?owner=bob#fragment", None)
            .0
            .unwrap_err()
            .to_string(),
        "No project named demo?owner=bob#fragment."
    );
}

#[test]
fn completions_offer_verb_and_values_at_the_correct_positions() {
    let output = std::process::Command::new("bash")
        .args([
            "-c",
            r#"
        source completions/sv.bash
        COMP_WORDS=(sv project ''); COMP_CWORD=2; _sv
        [[ ${COMPREPLY[*]} == visibility ]] || exit 1
        COMP_WORDS=(sv project visibility demo ''); COMP_CWORD=4; _sv
        [[ ${COMPREPLY[*]} == 'public private' ]] || exit 2
        COMP_WORDS=(sv project visibility ''); COMP_CWORD=3; _sv
        [[ ${#COMPREPLY[@]} == 0 ]] || exit 3
    "#,
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
