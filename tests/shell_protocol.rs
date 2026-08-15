//! `sv shell`, pinned to the TypeScript implementation.
//!
//! `tests/fixtures/shell.json` was recorded by driving ivaldi's real
//! `openShellSession` / `runShellPump` against a stubbed relay, a stubbed
//! workspace and a WebSocket double, and writing down everything that crossed a
//! boundary: the four HTTP requests of the connect chain (with each DPoP
//! proof's claims), every WebSocket frame the client sent, and the server
//! frames it was answered with.
//!
//! These tests replay the same answers into the Rust client and require the
//! same requests and the same frames back.
//!
//! Regenerate with:
//!   node tests/fixtures/generate-shell.mjs tests/fixtures <ivaldi>/packages/svartal-cli

mod common;

use std::collections::VecDeque;
use std::time::Duration;

use serde_json::{Value, json};

use common::{FakeTransport, fixture, json_response};
use svartal::api::{LinkRecord, Machine};
use svartal::dpop::{DpopKey, PrivateJwk};
use svartal::rpc::{RpcClient, RpcTransport, TransportError};
use svartal::shell::{
    self, InputPoll, LocalTerminal, OpenInput, PumpInput, ShellOutcome, describe_shell_outcome,
    detached_thread_id, shell_terminal_id,
};
use svartal::target::{ShellTarget, select_shell_target};
use svartal::terminal::{TerminalSize, Utf8Chunker, normalize_size};
use svartal::view::build_machines_view;

// -- target resolution -----------------------------------------------------

fn machines_view(second_workspace: bool, presence: &str) -> svartal::view::MachinesView {
    let mut environments = vec![json!({
        "id": "row-1",
        "environmentId": "env-primary",
        "label": "Primary",
        "kind": "personal",
        "lifecycleState": "active",
    })];
    if second_workspace {
        environments.push(json!({
            "id": "row-2",
            "environmentId": "env-second",
            "label": "Second",
            "kind": "workspace",
            "lifecycleState": "active",
        }));
    }
    let machines: Vec<Machine> = vec![
        serde_json::from_value(json!({
            "id": "machine-1",
            "name": "workbench",
            "origin": "donated",
            "lifecycleState": "open",
            "presence": presence,
            "lastSeenAt": null,
            "environments": environments,
        }))
        .unwrap(),
    ];
    let links: Vec<LinkRecord> = vec![
        serde_json::from_value(json!({
            "environmentId": "env-primary",
            "label": "Primary",
            "endpoint": {
                "httpBaseUrl": "https://workspace.example.com",
                "wsBaseUrl": "wss://workspace.example.com",
                "providerKind": "cloudflare_tunnel",
            },
            "linkedAt": "2026-08-01T10:00:00Z",
        }))
        .unwrap(),
    ];
    build_machines_view(&machines, &links)
}

#[test]
fn a_workspace_id_wins_over_every_other_match() {
    let view = machines_view(true, "unknown");
    let target = select_shell_target(&view, "env-primary").unwrap();
    assert_eq!(target.environment_id, "env-primary");
    // Case and surrounding space are not a different answer.
    assert_eq!(select_shell_target(&view, "  ENV-PRIMARY ").unwrap().environment_id, "env-primary");
    // A label resolves too, when it is the only thing that answers.
    assert_eq!(select_shell_target(&view, "Primary").unwrap().environment_id, "env-primary");
}

#[test]
fn one_word_for_two_workspaces_is_a_question_not_a_guess() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, "workbench").unwrap_err();
    let message = error.to_string();
    assert!(message.contains("matches more than one workspace"));
    assert!(message.contains("env-primary"));
    assert!(message.contains("env-second"));
    assert!(message.contains("MACHINE"), "the candidates are listed as a table");
}

#[test]
fn a_workspace_you_are_not_linked_to_is_refused_with_the_reason() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, "env-second").unwrap_err();
    assert!(error.to_string().contains("You are not linked to Second"));
}

#[test]
fn a_machine_that_reported_itself_offline_is_refused_but_silence_is_not() {
    let offline = machines_view(false, "offline");
    let error = select_shell_target(&offline, "env-primary").unwrap_err();
    assert!(error.to_string().contains("last reported that it is offline"));

    // `unknown` is the normal case for a machine that never checked in.
    let unknown = machines_view(false, "unknown");
    assert!(select_shell_target(&unknown, "env-primary").is_ok());
}

#[test]
fn a_name_nothing_answers_to_lists_what_is_reachable() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, "nowhere").unwrap_err();
    let message = error.to_string();
    assert!(message.contains("No workspace called nowhere"));
    assert!(message.contains("These are the ones you can reach"));
    assert!(message.contains("env-primary"));

    let empty = build_machines_view(&[], &[]);
    let error = select_shell_target(&empty, "nowhere").unwrap_err();
    assert!(error.to_string().contains("You cannot reach any workspace yet"));
}

#[test]
fn the_terminal_id_is_derived_from_the_workspace_id() {
    let fixture = fixture("shell.json");
    assert_eq!(
        shell_terminal_id(fixture["environmentId"].as_str().unwrap()),
        fixture["terminalId"].as_str().unwrap()
    );
    assert_eq!(shell_terminal_id("a b/c"), "shell-a-b-c");
    assert_eq!(shell_terminal_id("///"), "shell-workspace");
    assert_eq!(shell_terminal_id(""), "shell-workspace");
    assert_eq!(shell_terminal_id("-lead-and-trail-"), "shell-lead-and-trail");
    assert!(shell_terminal_id(&"x".repeat(400)).len() <= 128);
    assert_eq!(
        detached_thread_id(fixture["subject"].as_str().unwrap()),
        fixture["threadId"].as_str().unwrap()
    );
}

// -- the connect chain -----------------------------------------------------

fn key_of(fixture: &Value) -> DpopKey {
    let jwk: PrivateJwk = serde_json::from_value(fixture["privateJwk"].clone()).unwrap();
    DpopKey::from_private_jwk(&jwk).unwrap()
}

fn target_of(fixture: &Value) -> ShellTarget {
    ShellTarget {
        environment_id: fixture["environmentId"].as_str().unwrap().to_string(),
        label: fixture["target"]["label"].as_str().unwrap().to_string(),
        machine_name: Some(fixture["target"]["machineName"].as_str().unwrap().to_string()),
        linked: true,
        machine_presence: Some("unknown".to_string()),
    }
}

/// The stubbed relay and workspace, answering exactly what the fixture's run
/// was answered with.
fn recorded_responses(fixture: Value) -> FakeTransport {
    let relay = fixture["relayUrl"].as_str().unwrap().to_string();
    let http_base = fixture["httpBaseUrl"].as_str().unwrap().to_string();
    let environment_id = fixture["environmentId"].as_str().unwrap().to_string();
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{relay}/v1/client/dpop-token") {
            return json_response(
                200,
                &json!({
                    "access_token": "relay-access-token",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "DPoP",
                    "expires_in": 300,
                    "scope": "environment:connect",
                }),
            );
        }
        if url == format!("{relay}/v1/environments/{environment_id}/connect") {
            return json_response(
                200,
                &json!({
                    "environmentId": environment_id,
                    "endpoint": {
                        "httpBaseUrl": http_base,
                        "wsBaseUrl": "wss://workspace.example.com",
                        "providerKind": "cloudflare_tunnel",
                    },
                    "credential": "environment-credential",
                    "expiresAt": "2026-07-30T12:05:00.000Z",
                }),
            );
        }
        if url == format!("{http_base}/oauth/token") {
            return json_response(
                200,
                &json!({
                    "access_token": "workspace-access-token",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "Bearer",
                    "expires_in": 300,
                    "scope": "terminal:operate orchestration:read",
                }),
            );
        }
        if url == format!("{http_base}/api/auth/websocket-ticket") {
            return json_response(
                200,
                &json!({ "ticket": "ws-ticket-fixture", "expiresAt": "2026-07-30T12:05:00.000Z" }),
            );
        }
        json_response(404, &json!({ "error": "unexpected" }))
    })
}

fn proof_claims(proof: &str) -> Value {
    let payload = proof.split('.').nth(1).unwrap();
    serde_json::from_slice(&svartal::jwt::b64url_decode(payload).unwrap()).unwrap()
}

#[test]
fn the_connect_chain_makes_the_same_four_requests_as_the_reference() {
    let fixture = fixture("shell.json");
    let http = recorded_responses(fixture.clone());
    let key = key_of(&fixture);
    let target = target_of(&fixture);

    let connection = shell::connect_workspace(
        &http,
        &shell::ConnectInput {
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: shell::cli_client_metadata(),
        },
    )
    .unwrap();

    // The socket URL, including `/ws` and the ticket.
    assert_eq!(connection.socket_url, fixture["socketUrl"].as_str().unwrap());

    let expected = fixture["httpCalls"].as_array().unwrap();
    let actual = http.requests();
    assert_eq!(actual.len(), expected.len(), "one request per recorded call");
    for (call, request) in expected.iter().zip(actual.iter()) {
        let url = call["url"].as_str().unwrap();
        assert_eq!(request.url, url);
        assert_eq!(request.method, call["method"].as_str().unwrap());

        let header = |name: &str| {
            request
                .headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        match call["authorization"].as_str() {
            None => assert!(header("authorization").is_none(), "{url} carries no authorization"),
            Some(expected) => assert_eq!(header("authorization").as_deref(), Some(expected)),
        }

        // Every call is DPoP-bound, and each proof is bound to that call's URL
        // — and to the token it presents, when it presents one.
        let proof = header("dpop").expect("every request carries a proof");
        let claims = proof_claims(&proof);
        let recorded = &call["dpopClaims"];
        assert_eq!(claims["htm"], recorded["htm"], "{url}");
        assert_eq!(claims["htu"], recorded["htu"], "{url}");
        assert_eq!(claims["ath"], recorded["ath"], "{url}");

        // Bodies: form fields for the two token exchanges, JSON for connect.
        let recorded_body = call["body"].as_str().unwrap();
        match &request.body {
            Some(svartal::http::Body::Form(fields)) => {
                for (name, value) in fields {
                    let encoded = form_urlencoded_pair(name, value);
                    assert!(
                        recorded_body.contains(&encoded),
                        "{url} body is missing {name}={value}\nrecorded: {recorded_body}"
                    );
                }
                assert_eq!(
                    fields.len(),
                    recorded_body.split('&').count(),
                    "{url} sends the same number of fields"
                );
            }
            Some(svartal::http::Body::Json(value)) => {
                let recorded: Value = serde_json::from_str(recorded_body).unwrap();
                assert_eq!(value, &recorded, "{url}");
            }
            None => assert!(recorded_body.is_empty(), "{url} sends no body"),
        }
    }
}

fn form_urlencoded_pair(name: &str, value: &str) -> String {
    let encode = |text: &str| {
        url::form_urlencoded::Serializer::new(String::new()).append_pair("k", text).finish()
            [2..]
            .to_string()
    };
    format!("{}={}", encode(name), encode(value))
}

#[test]
fn the_workspace_token_asks_for_both_scopes() {
    let fixture = fixture("shell.json");
    let http = recorded_responses(fixture.clone());
    let key = key_of(&fixture);
    let target = target_of(&fixture);
    shell::connect_workspace(
        &http,
        &shell::ConnectInput {
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: shell::cli_client_metadata(),
        },
    )
    .unwrap();

    let form = http.last_form(&format!("{}/oauth/token", fixture["httpBaseUrl"].as_str().unwrap()));
    let value = |name: &str| {
        form.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()).unwrap_or_default()
    };
    // `orchestration:read` is load-bearing: the workspace gates the config
    // subscription behind it, and that is where the CLI learns the root.
    assert_eq!(value("scope"), "terminal:operate orchestration:read");
    assert_eq!(value("grant_type"), "urn:ietf:params:oauth:grant-type:token-exchange");
    assert_eq!(value("subject_token"), "environment-credential");
    assert_eq!(value("subject_token_type"), "urn:t3:params:oauth:token-type:environment-bootstrap");
    assert_eq!(value("client_label"), "svartal CLI");
    assert_eq!(value("client_device_type"), "desktop");
}

#[test]
fn a_grant_without_terminals_says_so_in_its_own_words() {
    let fixture = fixture("shell.json");
    let relay = fixture["relayUrl"].as_str().unwrap().to_string();
    let http_base = fixture["httpBaseUrl"].as_str().unwrap().to_string();
    let environment_id = fixture["environmentId"].as_str().unwrap().to_string();
    let http = FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{relay}/v1/client/dpop-token") {
            return json_response(
                200,
                &json!({
                    "access_token": "relay-access-token",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "DPoP",
                    "expires_in": 300,
                    "scope": "environment:connect",
                }),
            );
        }
        if url == format!("{relay}/v1/environments/{environment_id}/connect") {
            return json_response(
                200,
                &json!({
                    "environmentId": environment_id,
                    "endpoint": {
                        "httpBaseUrl": http_base,
                        "wsBaseUrl": "wss://workspace.example.com",
                        "providerKind": "cloudflare_tunnel",
                    },
                    "credential": "environment-credential",
                    "expiresAt": "2026-07-30T12:05:00.000Z",
                }),
            );
        }
        json_response(403, &json!({ "_tag": "EnvironmentScopeRequiredError", "scope": "terminal:operate" }))
    });
    let fixture_key = key_of(&fixture);
    let target = target_of(&fixture);

    let error = shell::connect_workspace(
        &http,
        &shell::ConnectInput {
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &fixture_key,
            client_metadata: shell::cli_client_metadata(),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not allow terminals"));
    assert!(!error.to_string().contains("Could not open a shell"));
}

// -- the RPC frames --------------------------------------------------------

/// Replays the fixture's server frames and records what the client sends.
struct ScriptedTransport {
    outgoing: Vec<Value>,
    incoming: VecDeque<Value>,
    /// Frames are released one at a time, when the script says the client has
    /// caught up, so the order the fixture recorded is the order replayed.
    release_after: VecDeque<usize>,
}

impl ScriptedTransport {
    fn new(server_frames: &[Value], release_after: Vec<usize>) -> Self {
        Self {
            outgoing: Vec::new(),
            incoming: server_frames.iter().cloned().collect(),
            release_after: release_after.into(),
        }
    }
}

impl RpcTransport for ScriptedTransport {
    fn recv(&mut self, _timeout: Duration) -> Result<Option<String>, TransportError> {
        let Some(&needed) = self.release_after.front() else {
            return Ok(None);
        };
        if self.outgoing.len() < needed {
            return Ok(None);
        }
        self.release_after.pop_front();
        match self.incoming.pop_front() {
            Some(frame) => Ok(Some(frame.to_string())),
            None => Ok(None),
        }
    }

    fn send(&mut self, text: &str) -> Result<(), TransportError> {
        self.outgoing.push(serde_json::from_str(text).unwrap());
        Ok(())
    }
}

struct ScriptedTerminal {
    size: TerminalSize,
    typed: VecDeque<String>,
    resizes: VecDeque<TerminalSize>,
    written: Vec<String>,
}

impl LocalTerminal for ScriptedTerminal {
    fn size(&self) -> TerminalSize {
        self.size
    }

    fn write(&mut self, data: &str) {
        self.written.push(data.to_string());
    }

    /// Types only once the replayed history and the first live output have
    /// been drawn, so the recorded order (attach, ack, ack, write) is the order
    /// this test reproduces.
    fn take_input(&mut self) -> InputPoll {
        if self.written.len() < 2 {
            return InputPoll::None;
        }
        match self.typed.pop_front() {
            Some(data) => InputPoll::Data(data),
            None => InputPoll::None,
        }
    }

    fn take_resize(&mut self) -> bool {
        if self.resizes.is_empty() || !self.typed.is_empty() || self.written.len() < 2 {
            return false;
        }
        self.size = self.resizes.pop_front().expect("checked");
        true
    }
}

/// The recorded client frames, minus the tracing fields the Rust client does
/// not send (`traceId`, `spanId`, `sampled` are optional in `RequestEncoded`).
fn without_tracing(frame: &Value) -> Value {
    let mut frame = frame.clone();
    if let Some(object) = frame.as_object_mut() {
        object.remove("traceId");
        object.remove("spanId");
        object.remove("sampled");
    }
    frame
}

#[test]
fn the_rpc_frames_match_the_reference_client() {
    let fixture = fixture("shell.json");
    let server_frames: Vec<Value> = fixture["serverFrames"].as_array().unwrap().clone();
    // The fixture's answers, released as the client reaches each step: the
    // config exit once the request is out, the open exit after it, the first
    // chunk after the attach, the second after its ack, then the write and
    // resize exits, then the event that ends the shell.
    let transport = ScriptedTransport::new(&server_frames, vec![1, 2, 3, 4, 6, 7, 7]);
    let mut rpc = RpcClient::new(transport);

    let session = shell::open_shell(
        &mut rpc,
        &OpenInput {
            label: "Primary",
            subject: fixture["subject"].as_str().unwrap(),
            terminal_id: None,
            environment_id: fixture["environmentId"].as_str().unwrap(),
            size: normalize_size(
                Some(fixture["size"]["cols"].as_u64().unwrap() as u16),
                Some(fixture["size"]["rows"].as_u64().unwrap() as u16),
            ),
        },
    )
    .unwrap();
    assert_eq!(session.cwd, fixture["workspaceCwd"].as_str().unwrap());
    assert_eq!(session.terminal_id, fixture["terminalId"].as_str().unwrap());
    assert_eq!(session.thread_id, fixture["threadId"].as_str().unwrap());
    // The fixture's snapshot is `starting` with no pid: a fresh shell.
    assert!(!session.reattached);

    let mut terminal = ScriptedTerminal {
        size: normalize_size(Some(120), Some(40)),
        typed: VecDeque::from(vec!["echo hello\r".to_string()]),
        resizes: VecDeque::from(vec![normalize_size(Some(100), Some(30))]),
        written: Vec::new(),
    };
    let outcome = shell::run_shell_pump(
        &mut rpc,
        &mut terminal,
        &PumpInput { session: &session, label: "Primary", subject: fixture["subject"].as_str().unwrap() },
    )
    .unwrap();

    assert_eq!(outcome, ShellOutcome::Exited { exit_code: Some(0) });
    // History first, then live output — exactly what the reference wrote.
    assert_eq!(
        terminal.written,
        fixture["terminalWrites"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    );

    let expected: Vec<Value> =
        fixture["clientFrames"].as_array().unwrap().iter().map(without_tracing).collect();
    let actual = &rpc.transport_mut().outgoing;
    assert_eq!(
        actual.len(),
        expected.len(),
        "frame count differs\nexpected: {expected:#?}\nactual: {actual:#?}"
    );
    for (index, (actual, expected)) in actual.iter().zip(expected.iter()).enumerate() {
        assert_eq!(actual, expected, "frame {index} differs");
    }
}

#[test]
fn a_reattached_shell_is_recognised_by_its_running_pid() {
    let fixture = fixture("shell.json");
    let config = fixture["serverFrames"][0].clone();
    let running = json!({
        "_tag": "Exit",
        "requestId": "1",
        "exit": {
            "_tag": "Success",
            "value": {
                "threadId": fixture["threadId"],
                "terminalId": fixture["terminalId"],
                "cwd": fixture["workspaceCwd"],
                "worktreePath": null,
                "status": "running",
                "pid": 4_242,
                "history": "",
                "exitCode": null,
                "exitSignal": null,
                "label": "shell",
                "updatedAt": "2026-07-30T12:00:00.000Z",
            },
        },
    });
    let transport = ScriptedTransport::new(&[config, running], vec![1, 2]);
    let mut rpc = RpcClient::new(transport);
    let session = shell::open_shell(
        &mut rpc,
        &OpenInput {
            label: "Primary",
            subject: fixture["subject"].as_str().unwrap(),
            terminal_id: None,
            environment_id: fixture["environmentId"].as_str().unwrap(),
            size: normalize_size(Some(120), Some(40)),
        },
    )
    .unwrap();
    assert!(session.reattached);
}

#[test]
fn a_namespace_refusal_is_told_apart_from_every_other_failure() {
    let fixture = fixture("shell.json");
    let config = fixture["serverFrames"][0].clone();
    let refused = json!({
        "_tag": "Exit",
        "requestId": "1",
        "exit": {
            "_tag": "Failure",
            "cause": [{
                "_tag": "Fail",
                "error": { "_tag": "EnvironmentAuthorizationError", "message": "not your namespace" },
            }],
        },
    });
    let transport = ScriptedTransport::new(&[config, refused], vec![1, 2]);
    let mut rpc = RpcClient::new(transport);
    let error = shell::open_shell(
        &mut rpc,
        &OpenInput {
            label: "Primary",
            subject: "someone",
            terminal_id: Some("shell-x"),
            environment_id: "env",
            size: normalize_size(Some(80), Some(24)),
        },
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("would not open a shell for someone"));
    assert!(message.contains("does not agree that this is who you are"));
}

#[test]
fn every_way_a_shell_ends_has_its_own_sentence() {
    assert_eq!(
        describe_shell_outcome(&ShellOutcome::Exited { exit_code: Some(0) }, "Primary"),
        "Shell on Primary ended."
    );
    assert_eq!(
        describe_shell_outcome(&ShellOutcome::Exited { exit_code: None }, "Primary"),
        "Shell on Primary ended."
    );
    assert_eq!(
        describe_shell_outcome(&ShellOutcome::Exited { exit_code: Some(3) }, "Primary"),
        "Shell on Primary ended with status 3."
    );
    assert_eq!(
        describe_shell_outcome(&ShellOutcome::Closed, "Primary"),
        "Shell on Primary was closed."
    );
    assert_eq!(
        describe_shell_outcome(&ShellOutcome::Detached, "Primary"),
        "Left the shell on Primary running. Run the same command to pick it up again."
    );
}

// -- the local terminal ----------------------------------------------------

#[test]
fn a_multi_byte_key_split_across_two_reads_stays_one_character() {
    let mut chunker = Utf8Chunker::default();
    // "é" is 0xC3 0xA9; a read boundary can land between them.
    assert_eq!(chunker.push(&[0x61, 0xC3]), "a");
    assert_eq!(chunker.push(&[0xA9, 0x62]), "éb");
    // Invalid bytes are not held forever; they pass through as replacements.
    assert_eq!(chunker.push(&[0xFF]), "\u{fffd}");
}

#[test]
fn terminal_sizes_are_clamped_to_what_the_workspace_accepts() {
    assert_eq!(normalize_size(Some(120), Some(40)), TerminalSize { cols: 120, rows: 40 });
    assert_eq!(normalize_size(None, None), TerminalSize { cols: 80, rows: 24 });
    assert_eq!(normalize_size(Some(0), Some(0)), TerminalSize { cols: 80, rows: 24 });
    assert_eq!(normalize_size(Some(4_000), Some(4_000)), TerminalSize { cols: 1_000, rows: 500 });
}
