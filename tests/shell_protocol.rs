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
    self, InputPoll, LocalTerminal, OpenInput, PumpInput, ShellOutcome, TerminalKind,
    describe_shell_outcome, detached_thread_id, terminal_id,
};
use svartal::shortnames::Shortnames;
use svartal::target::{ShellTarget, select_shell_target, select_target};
use svartal::terminal::{TerminalSize, Utf8Chunker, normalize_size};
use svartal::view::build_machines_view;

// -- target resolution -----------------------------------------------------

/// Resolution with nothing named. The short-name rules have their own tests in
/// `shortnames_and_envs.rs`; these are about the rules underneath them.
fn no_names() -> Shortnames {
    Shortnames::new()
}

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
    let target = select_shell_target(&view, &no_names(), "env-primary").unwrap();
    assert_eq!(target.environment_id, "env-primary");
    // Case and surrounding space are not a different answer.
    assert_eq!(select_shell_target(&view, &no_names(), "  ENV-PRIMARY ").unwrap().environment_id, "env-primary");
    // A label resolves too, when it is the only thing that answers.
    assert_eq!(select_shell_target(&view, &no_names(), "Primary").unwrap().environment_id, "env-primary");
}

#[test]
fn one_word_for_two_workspaces_is_a_question_not_a_guess() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, &no_names(), "workbench").unwrap_err();
    let message = error.to_string();
    assert!(message.contains("matches more than one workspace"));
    assert!(message.contains("env-primary"));
    assert!(message.contains("env-second"));
    assert!(message.contains("MACHINE"), "the candidates are listed as a table");
}

#[test]
fn a_workspace_you_are_not_linked_to_is_refused_with_the_reason() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, &no_names(), "env-second").unwrap_err();
    assert!(error.to_string().contains("You are not linked to Second"));
}

#[test]
fn a_machine_that_reported_itself_offline_is_refused_but_silence_is_not() {
    let offline = machines_view(false, "offline");
    let error = select_shell_target(&offline, &no_names(), "env-primary").unwrap_err();
    assert!(error.to_string().contains("last reported that it is offline"));

    // `unknown` is the normal case for a machine that never checked in.
    let unknown = machines_view(false, "unknown");
    assert!(select_shell_target(&unknown, &no_names(), "env-primary").is_ok());
}

#[test]
fn a_name_nothing_answers_to_lists_what_is_reachable() {
    let view = machines_view(true, "unknown");
    let error = select_shell_target(&view, &no_names(), "nowhere").unwrap_err();
    let message = error.to_string();
    assert!(message.contains("No workspace called nowhere"));
    assert!(message.contains("These are the ones you can reach"));
    assert!(message.contains("env-primary"));

    let empty = build_machines_view(&[], &[]);
    let error = select_shell_target(&empty, &no_names(), "nowhere").unwrap_err();
    assert!(error.to_string().contains("You cannot reach any workspace yet"));
}

#[test]
fn the_terminal_id_is_derived_from_the_workspace_id() {
    let fixture = fixture("shell.json");
    let shell = TerminalKind::Shell;
    assert_eq!(
        terminal_id(shell, fixture["environmentId"].as_str().unwrap()),
        fixture["terminalId"].as_str().unwrap()
    );
    assert_eq!(terminal_id(shell, "a b/c"), "shell-a-b-c");
    assert_eq!(terminal_id(shell, "///"), "shell-workspace");
    assert_eq!(terminal_id(shell, ""), "shell-workspace");
    assert_eq!(terminal_id(shell, "-lead-and-trail-"), "shell-lead-and-trail");
    assert!(terminal_id(shell, &"x".repeat(400)).len() <= 128);
    assert_eq!(
        detached_thread_id(shell, fixture["subject"].as_str().unwrap()),
        fixture["threadId"].as_str().unwrap()
    );
}

#[test]
fn a_claude_terminal_lives_in_its_own_namespace_beside_the_shell() {
    let fixture = fixture("shell.json");
    let subject = fixture["subject"].as_str().unwrap();
    let environment = fixture["environmentId"].as_str().unwrap();
    // Same subject, same workspace, two terminals: the prefixes are what keep
    // a person's shell and their Claude session apart.
    assert_eq!(detached_thread_id(TerminalKind::Claude, subject), format!("svartal-claude:{subject}"));
    assert_ne!(
        detached_thread_id(TerminalKind::Claude, subject),
        detached_thread_id(TerminalKind::Shell, subject)
    );
    assert_eq!(
        terminal_id(TerminalKind::Claude, environment),
        format!("claude-{}", &fixture["terminalId"].as_str().unwrap()["shell-".len()..])
    );
    assert_eq!(terminal_id(TerminalKind::Claude, "a b/c"), "claude-a-b-c");
    assert!(terminal_id(TerminalKind::Claude, &"x".repeat(400)).len() <= 128);
}

#[test]
fn one_reachable_workspace_needs_no_argument_and_two_do() {
    // `sv claude` with no target: one reachable workspace is not a guess.
    let single = machines_view(false, "unknown");
    assert_eq!(select_target(&single, &no_names(), None).unwrap().environment_id, "env-primary");
    assert_eq!(select_target(&single, &no_names(), Some("  ")).unwrap().environment_id, "env-primary");
    assert_eq!(select_target(&single, &no_names(), Some("Primary")).unwrap().environment_id, "env-primary");

    // The second workspace in this view is unlinked, so it is not reachable
    // and does not make the choice ambiguous.
    let two = machines_view(true, "unknown");
    assert_eq!(select_target(&two, &no_names(), None).unwrap().environment_id, "env-primary");

    let none = svartal::view::build_machines_view(&[], &[]);
    let error = select_target(&none, &no_names(), None).unwrap_err();
    assert!(error.to_string().contains("cannot reach any workspace yet"));
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
            kind: TerminalKind::Shell,
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: shell::cli_client_metadata(),
            scopes: &svartal::workspace::SHELL_SCOPES,
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
            kind: TerminalKind::Shell,
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: shell::cli_client_metadata(),
            scopes: &svartal::workspace::SHELL_SCOPES,
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
    assert_eq!(value("subject_token_type"), "urn:svartal:params:oauth:token-type:environment-bootstrap");
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
            kind: TerminalKind::Shell,
            relay_url: fixture["relayUrl"].as_str().unwrap(),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &fixture_key,
            client_metadata: shell::cli_client_metadata(),
            scopes: &svartal::workspace::SHELL_SCOPES,
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
            kind: TerminalKind::Shell,
            label: "Primary",
            subject: fixture["subject"].as_str().unwrap(),
            terminal_id: None,
            environment_id: fixture["environmentId"].as_str().unwrap(),
            size: normalize_size(
                Some(fixture["size"]["cols"].as_u64().unwrap() as u16),
                Some(fixture["size"]["rows"].as_u64().unwrap() as u16),
            ),
            term: fixture["term"].as_str().map(str::to_string),
            colorterm: None,
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

/// Open a shell against one scripted `terminal.open` answer, and hand back both
/// the session and the payload the CLI put on the wire.
fn open_against(
    kind: TerminalKind,
    open_value: Value,
    term: Option<&str>,
    colorterm: Option<&str>,
) -> (shell::ShellSession, Vec<Value>) {
    let fixture = fixture("shell.json");
    let config = fixture["serverFrames"][0].clone();
    let open = json!({
        "_tag": "Exit",
        "requestId": "1",
        "exit": { "_tag": "Success", "value": open_value },
    });
    let transport = ScriptedTransport::new(&[config, open], vec![1, 2]);
    let mut rpc = RpcClient::new(transport);
    let session = shell::open_shell(
        &mut rpc,
        &OpenInput {
            kind,
            label: "Primary",
            subject: fixture["subject"].as_str().unwrap(),
            terminal_id: None,
            environment_id: fixture["environmentId"].as_str().unwrap(),
            size: normalize_size(Some(120), Some(40)),
            term: term.map(str::to_string),
            colorterm: colorterm.map(str::to_string),
        },
    )
    .unwrap();
    let sent = rpc.transport_mut().outgoing.clone();
    (session, sent)
}

/// A `terminal.open` answer, with whatever the test wants to say on top.
fn open_snapshot(values: Value) -> Value {
    let fixture = fixture("shell.json");
    let mut snapshot = json!({
        "threadId": fixture["threadId"],
        "terminalId": fixture["terminalId"],
        "cwd": fixture["workspaceCwd"],
        "worktreePath": null,
        "status": "starting",
        "pid": null,
        "history": "",
        "exitCode": null,
        "exitSignal": null,
        "label": "shell",
        "updatedAt": "2026-07-30T12:00:00.000Z",
    });
    let (Some(target), Some(values)) = (snapshot.as_object_mut(), values.as_object()) else {
        return snapshot;
    };
    for (key, value) in values {
        target.insert(key.clone(), value.clone());
    }
    snapshot
}

/// The one thing a client cannot work out for itself.
///
/// A freshly spawned PTY is reported `running` with a pid within milliseconds,
/// so the old guess called a shell that had never existed a reattach — and
/// said "Back in your shell" on every fresh terminal. The workspace now answers
/// the question itself, and its answer wins over the snapshot.
#[test]
fn a_terminal_the_workspace_says_it_created_is_not_a_reattach() {
    let (session, _) = open_against(
        TerminalKind::Shell,
        open_snapshot(json!({ "status": "running", "pid": 4_242, "created": true })),
        None,
        None,
    );
    assert!(!session.reattached);
}

#[test]
fn a_terminal_the_workspace_found_running_is_a_reattach() {
    let (session, _) = open_against(
        TerminalKind::Shell,
        open_snapshot(json!({ "status": "running", "pid": 4_242, "created": false })),
        None,
        None,
    );
    assert!(session.reattached);
}

/// A provider terminal has no local pid at all — its process is in the runner
/// container — so the old guess degraded to "running at all", which is true of
/// every Claude terminal the moment it starts.
#[test]
fn a_fresh_claude_terminal_is_not_greeted_as_one_you_were_already_in() {
    let (session, _) = open_against(
        TerminalKind::Claude,
        open_snapshot(json!({ "status": "running", "pid": null, "created": true })),
        None,
        None,
    );
    assert!(!session.reattached);
}

/// The old-guess fallback for a workspace without `created` was pinned here on
/// the theory that calling a long-running session new was the worse error. Live
/// use overturned it: three fresh opens against the deployed v0.1.47 workspace
/// (shell and Claude, 2026-08-19) were all greeted "Back in your \u{2026}", because a
/// fresh PTY is already running with a pid at snapshot time — the guess can
/// only ever answer "reattached". A missing field now reads as fresh, and only
/// an explicit `created: false` reads as a reattach.
#[test]
fn a_workspace_without_created_reads_as_fresh() {
    let (shell_session, _) = open_against(
        TerminalKind::Shell,
        open_snapshot(json!({ "status": "running", "pid": 4_242 })),
        None,
        None,
    );
    assert!(!shell_session.reattached);

    let (fresh, _) = open_against(
        TerminalKind::Shell,
        open_snapshot(json!({ "status": "starting", "pid": null })),
        None,
        None,
    );
    assert!(!fresh.reattached);

    let (claude, _) = open_against(
        TerminalKind::Claude,
        open_snapshot(json!({ "status": "running", "pid": null })),
        None,
        None,
    );
    assert!(!claude.reattached);
}

/// `TERM` names a terminfo entry; `COLORTERM` is the separate signal that says
/// truecolour really renders here. Without it an agent TUI on the far side
/// quietly downgrades to 256 colours.
#[test]
fn the_open_call_carries_this_terminals_colour_capability() {
    let (session, sent) = open_against(
        TerminalKind::Shell,
        open_snapshot(json!({})),
        Some("xterm-ghostty"),
        Some("truecolor"),
    );
    let open = sent.iter().find(|frame| frame["tag"] == "terminal.open").expect("the open frame");
    assert_eq!(open["payload"]["term"], json!("xterm-ghostty"));
    assert_eq!(open["payload"]["colorterm"], json!("truecolor"));
    assert_eq!(session.colorterm.as_deref(), Some("truecolor"));
}

#[test]
fn a_terminal_with_no_colour_capability_sends_no_key_at_all() {
    let (session, sent) = open_against(TerminalKind::Shell, open_snapshot(json!({})), None, None);
    let open = sent.iter().find(|frame| frame["tag"] == "terminal.open").expect("the open frame");
    // Not an explicit null: the workspace must not be told about a capability
    // nobody reported, and it has no default to fall back to either.
    assert!(open["payload"].get("colorterm").is_none());
    assert!(open["payload"].get("term").is_none());
    assert_eq!(session.colorterm, None);
}

#[test]
fn a_reattached_shell_is_recognised_by_the_workspaces_answer() {
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
                "created": false,
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
            kind: TerminalKind::Shell,
            label: "Primary",
            subject: fixture["subject"].as_str().unwrap(),
            terminal_id: None,
            environment_id: fixture["environmentId"].as_str().unwrap(),
            size: normalize_size(Some(120), Some(40)),
            term: None,
            colorterm: None,
        },
    )
    .unwrap();
    assert!(session.reattached);
}

#[test]
fn a_terminal_that_could_not_start_says_what_the_workspace_said() {
    // The workspace opens the terminal, then fails to start what belongs
    // behind it: no authorized Claude credential, a credential that is not
    // brokered, no broker on that machine at all. It puts the reason on the
    // terminal's own screen, and the CLI repeats it word for word rather than
    // inventing a friendlier sentence that says less.
    let fixture = fixture("shell.json");
    let config = fixture["serverFrames"][0].clone();
    let refusal = "Credential 'Claude work account' is not delivered through the machine broker, \
                   so it cannot run an interactive Claude terminal.";
    let failed = json!({
        "_tag": "Exit",
        "requestId": "1",
        "exit": {
            "_tag": "Success",
            "value": {
                "threadId": "svartal-claude:user-1",
                "terminalId": "claude-env-primary",
                "cwd": fixture["workspaceCwd"],
                "worktreePath": null,
                "status": "error",
                "pid": null,
                "history": format!("{refusal}\n"),
                "exitCode": null,
                "exitSignal": null,
                "label": "Claude",
                "updatedAt": "2026-07-30T12:00:00.000Z",
            },
        },
    });
    let transport = ScriptedTransport::new(&[config, failed], vec![1, 2]);
    let mut rpc = RpcClient::new(transport);
    let error = shell::open_shell(
        &mut rpc,
        &OpenInput {
            kind: TerminalKind::Claude,
            label: "Primary",
            subject: "user-1",
            terminal_id: None,
            environment_id: "env-primary",
            size: normalize_size(Some(80), Some(24)),
            term: None,
            colorterm: None,
        },
    )
    .unwrap_err();
    let message = error.to_string();
    assert!(message.starts_with("Could not start your Claude terminal on Primary: "));
    assert!(message.contains(refusal), "the workspace's own sentence, verbatim: {message}");
}

#[test]
fn every_way_a_claude_terminal_ends_has_the_claude_sentence() {
    assert_eq!(
        describe_shell_outcome(TerminalKind::Claude, &ShellOutcome::Exited { exit_code: None }, "Primary"),
        "Claude on Primary ended."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Claude, &ShellOutcome::Closed, "Primary"),
        "Claude on Primary was closed."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Claude, &ShellOutcome::Detached, "Primary"),
        "Left the Claude terminal on Primary running. Run the same command to pick it up again."
    );
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
            kind: TerminalKind::Shell,
            label: "Primary",
            subject: "someone",
            terminal_id: Some("shell-x"),
            environment_id: "env",
            size: normalize_size(Some(80), Some(24)),
            term: None,
            colorterm: None,
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
        describe_shell_outcome(TerminalKind::Shell, &ShellOutcome::Exited { exit_code: Some(0) }, "Primary"),
        "Shell on Primary ended."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Shell, &ShellOutcome::Exited { exit_code: None }, "Primary"),
        "Shell on Primary ended."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Shell, &ShellOutcome::Exited { exit_code: Some(3) }, "Primary"),
        "Shell on Primary ended with status 3."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Shell, &ShellOutcome::Closed, "Primary"),
        "Shell on Primary was closed."
    );
    assert_eq!(
        describe_shell_outcome(TerminalKind::Shell, &ShellOutcome::Detached, "Primary"),
        "Left the shell on Primary running. Run the same command to pick it up again."
    );
}

// -- closing from outside ---------------------------------------------------

/// The metadata snapshot chunk `sv close` reads first. `terminals` carries the
/// sessions the workspace has live; the close is only sent when the asked-for
/// one is among them.
fn metadata_snapshot(terminals: &[(&str, &str)]) -> Value {
    json!({
        "_tag": "Chunk",
        "requestId": "0",
        "values": [{
            "type": "snapshot",
            "terminals": terminals
                .iter()
                .map(|(thread_id, terminal_id)| json!({
                    "threadId": thread_id,
                    "terminalId": terminal_id,
                    "cwd": "/workspace",
                    "worktreePath": null,
                    "status": "running",
                    "pid": 4_242,
                    "exitCode": null,
                    "exitSignal": null,
                    "hasRunningSubprocess": false,
                    "label": "shell",
                    "updatedAt": "2026-08-18T12:00:00.000Z",
                }))
                .collect::<Vec<_>>(),
        }],
    })
}

fn close_success() -> Value {
    // `WsTerminalCloseRpc` declares no success schema; the workspace answers
    // with an empty exit either way. The probe is what tells the two apart.
    json!({
        "_tag": "Exit",
        "requestId": "1",
        "exit": { "_tag": "Success", "value": null },
    })
}

fn run_close(
    kind: TerminalKind,
    terminal_id_override: Option<&str>,
    server_frames: &[Value],
    release_after: Vec<usize>,
) -> (Result<shell::CloseOutcome, shell::ShellError>, Vec<Value>) {
    let transport = ScriptedTransport::new(server_frames, release_after);
    let mut rpc = RpcClient::new(transport);
    let outcome = shell::close_shell(
        &mut rpc,
        &shell::CloseInput {
            kind,
            label: "Primary",
            subject: "user-1",
            terminal_id: terminal_id_override,
            environment_id: "env-primary",
        },
    );
    let frames = rpc.transport_mut().outgoing.clone();
    (outcome, frames)
}

#[test]
fn close_reads_the_snapshot_acks_it_and_sends_the_exact_close_frame() {
    let (outcome, frames) = run_close(
        TerminalKind::Shell,
        None,
        &[
            metadata_snapshot(&[("svartal-shell:user-1", "shell-env-primary")]),
            close_success(),
        ],
        // The snapshot once the subscription is out; the close's exit once the
        // close request is out (request, ack, interrupt, close).
        vec![1, 4],
    );
    assert_eq!(outcome.unwrap(), shell::CloseOutcome::Closed);
    assert_eq!(
        frames,
        vec![
            json!({"_tag": "Request", "id": "0", "tag": "subscribeTerminalMetadata", "payload": {}, "headers": []}),
            json!({"_tag": "Ack", "requestId": "0"}),
            json!({"_tag": "Interrupt", "requestId": "0"}),
            json!({"_tag": "Request", "id": "1", "tag": "terminal.close", "payload": {"threadId": "svartal-shell:user-1", "terminalId": "shell-env-primary"}, "headers": []}),
        ]
    );
}

#[test]
fn a_claude_close_names_the_claude_namespace_and_id() {
    let (outcome, frames) = run_close(
        TerminalKind::Claude,
        None,
        &[
            metadata_snapshot(&[
                // The person's shell on the same workspace is not what
                // `sv close claude` was asked about.
                ("svartal-shell:user-1", "shell-env-primary"),
                ("svartal-claude:user-1", "claude-env-primary"),
            ]),
            close_success(),
        ],
        vec![1, 4],
    );
    assert_eq!(outcome.unwrap(), shell::CloseOutcome::Closed);
    assert_eq!(
        frames[3],
        json!({"_tag": "Request", "id": "1", "tag": "terminal.close", "payload": {"threadId": "svartal-claude:user-1", "terminalId": "claude-env-primary"}, "headers": []}),
    );
}

#[test]
fn a_terminal_that_is_not_in_the_snapshot_gets_no_close_call_at_all() {
    // The other kind's terminal is there; the asked-for one is not. Nothing
    // is sent that could tear anything down.
    let (outcome, frames) = run_close(
        TerminalKind::Claude,
        None,
        &[metadata_snapshot(&[("svartal-shell:user-1", "shell-env-primary")])],
        vec![1],
    );
    assert_eq!(outcome.unwrap(), shell::CloseOutcome::NothingRunning);
    assert_eq!(
        frames,
        vec![
            json!({"_tag": "Request", "id": "0", "tag": "subscribeTerminalMetadata", "payload": {}, "headers": []}),
            json!({"_tag": "Ack", "requestId": "0"}),
            json!({"_tag": "Interrupt", "requestId": "0"}),
        ]
    );
}

#[test]
fn a_terminal_id_override_is_the_id_the_close_names() {
    let (outcome, frames) = run_close(
        TerminalKind::Shell,
        Some("shell-second"),
        &[
            metadata_snapshot(&[
                ("svartal-shell:user-1", "shell-env-primary"),
                ("svartal-shell:user-1", "shell-second"),
            ]),
            close_success(),
        ],
        vec![1, 4],
    );
    assert_eq!(outcome.unwrap(), shell::CloseOutcome::Closed);
    assert_eq!(frames[3]["payload"], json!({"threadId": "svartal-shell:user-1", "terminalId": "shell-second"}));
}

#[test]
fn every_answer_close_can_give_has_its_own_sentence() {
    assert_eq!(
        shell::describe_close_outcome(TerminalKind::Shell, shell::CloseOutcome::Closed, "Primary"),
        "Closed the shell on Primary."
    );
    assert_eq!(
        shell::describe_close_outcome(TerminalKind::Claude, shell::CloseOutcome::Closed, "Primary"),
        "Closed the Claude terminal on Primary."
    );
    assert_eq!(
        shell::describe_close_outcome(TerminalKind::Shell, shell::CloseOutcome::NothingRunning, "Primary"),
        "No shell was running on Primary."
    );
    assert_eq!(
        shell::describe_close_outcome(TerminalKind::Claude, shell::CloseOutcome::NothingRunning, "Primary"),
        "No Claude terminal was running on Primary."
    );
}

#[test]
fn a_close_that_fails_says_close_not_open() {
    let refused = json!({
        "_tag": "Exit",
        "requestId": "0",
        "exit": {
            "_tag": "Failure",
            "cause": [{ "_tag": "Fail", "error": { "_tag": "SomeStreamError", "message": "the stream broke" } }],
        },
    });
    let (outcome, _) = run_close(TerminalKind::Shell, None, &[refused], vec![1]);
    let message = outcome.unwrap_err().to_string();
    assert_eq!(message, "Could not close the shell on Primary: the stream broke");
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
