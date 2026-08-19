//! `sv close`, end to end from the command layer.
//!
//! The HTTP half — identity, listings, and the whole connect chain — runs over
//! the recorded `FakeTransport` answers; the WebSocket step is injected
//! through `commands::close_with`, so these tests script the wire and read the
//! exact sentences a person gets. The frame-level contract has its own tests
//! in `shell_protocol.rs`; this file is about what the command does with it.

mod common;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Write;
use std::rc::Rc;
use std::time::Duration;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::browser::NoBrowser;
use svartal::commands::{self, CliError, Context};
use svartal::config::resolve_config;
use svartal::rpc::{RpcTransport, TransportError};
use svartal::shell::TerminalKind;
use svartal::store::MemoryTokenStorage;

const WORKSPACE_BASE: &str = "https://workspace.example.test";

const MACHINES_BODY: &str = r#"{
  "data": [
    {
      "id": "machine-1",
      "name": "workbench",
      "origin": "donated",
      "lifecycleState": "open",
      "presence": "online",
      "lastSeenAt": "2026-08-13T09:00:00Z",
      "environments": [
        { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "lifecycleState": "active" },
        { "id": "row-2", "environmentId": "env-second", "label": "Second", "kind": "workspace", "lifecycleState": "active" }
      ]
    }
  ]
}"#;

/// The same machine, having last reported itself off.
const OFFLINE_MACHINES_BODY: &str = r#"{
  "data": [
    {
      "id": "machine-1",
      "name": "workbench",
      "origin": "donated",
      "lifecycleState": "open",
      "presence": "offline",
      "lastSeenAt": "2026-08-13T09:00:00Z",
      "environments": [
        { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "lifecycleState": "active" }
      ]
    }
  ]
}"#;

const ENVIRONMENTS_BODY: &str = r#"{
  "environments": [
    {
      "environmentId": "env-primary",
      "label": "Primary",
      "endpoint": { "httpBaseUrl": "https://workspace.example.test", "wsBaseUrl": "wss://workspace.example.test", "providerKind": "cloudflare_tunnel" },
      "linkedAt": "2026-08-01T10:00:00Z"
    }
  ]
}"#;

/// The WebSocket, as frames to hand the client and a shared recording of what
/// it sent.
struct ScriptedWs {
    incoming: VecDeque<Value>,
    sent: Rc<RefCell<Vec<Value>>>,
}

impl RpcTransport for ScriptedWs {
    fn recv(&mut self, _timeout: Duration) -> Result<Option<String>, TransportError> {
        Ok(self.incoming.pop_front().map(|frame| frame.to_string()))
    }

    fn send(&mut self, text: &str) -> Result<(), TransportError> {
        self.sent.borrow_mut().push(serde_json::from_str(text).unwrap());
        Ok(())
    }
}

/// The snapshot the workspace's metadata stream opens with.
fn snapshot_chunk(terminals: &[(&str, &str)]) -> Value {
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

fn close_exit() -> Value {
    json!({ "_tag": "Exit", "requestId": "1", "exit": { "_tag": "Success", "value": null } })
}

struct Harness {
    fixture: Value,
    directory: TempDir,
}

impl Harness {
    fn new(tag: &str) -> Self {
        Self { fixture: fixture("oidc.json"), directory: TempDir::new(tag) }
    }

    fn subject(&self) -> &str {
        self.fixture["subject"].as_str().unwrap()
    }

    /// Run one command against the recorded identity, listings and connect
    /// chain. The transport comes back so a test can look at what was asked.
    fn run<F>(&self, machines_body: &str, command: F) -> (Result<(), CliError>, String, FakeTransport)
    where
        F: FnOnce(&Context<'_>, &mut dyn Write) -> Result<(), CliError>,
    {
        let fixture = self.fixture.clone();
        let issuer = fixture["issuer"].as_str().unwrap().to_string();
        let relay = fixture["relayUrl"].as_str().unwrap().to_string();
        let machines: Value = serde_json::from_str(machines_body).unwrap();
        let http = FakeTransport::new(move |request| {
            let url = request.url.as_str();
            if url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &fixture["discovery"]);
            }
            if url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &fixture["jwks"]);
            }
            if url == format!("{issuer}/api/v1/client/machines") {
                return json_response(200, &machines);
            }
            if url == format!("{relay}/v1/environments") {
                return json_response(200, &serde_json::from_str(ENVIRONMENTS_BODY).unwrap());
            }
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
            if url == format!("{relay}/v1/environments/env-primary/connect") {
                return json_response(
                    200,
                    &json!({
                        "environmentId": "env-primary",
                        "endpoint": {
                            "httpBaseUrl": WORKSPACE_BASE,
                            "wsBaseUrl": "wss://workspace.example.test",
                            "providerKind": "cloudflare_tunnel",
                        },
                        "credential": "environment-credential",
                        "expiresAt": "2026-08-18T12:05:00.000Z",
                    }),
                );
            }
            if url == format!("{WORKSPACE_BASE}/oauth/token") {
                return json_response(
                    200,
                    &json!({
                        "access_token": "workspace-access-token",
                        "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                        "token_type": "Bearer",
                        "expires_in": 300,
                        "scope": "terminal:operate",
                    }),
                );
            }
            if url == format!("{WORKSPACE_BASE}/api/auth/websocket-ticket") {
                return json_response(
                    200,
                    &json!({ "ticket": "ws-ticket", "expiresAt": "2026-08-18T12:05:00.000Z" }),
                );
            }
            json_response(404, &json!({ "error": "unexpected" }))
        });
        let storage = MemoryTokenStorage::with_value(&self.fixture["storedTokens"].to_string());
        let environment = [
            ("HOME".to_string(), "/home/person".to_string()),
            // Never the real `~/.config/svartal`.
            (
                "SVARTAL_CONFIG_DIR".to_string(),
                self.directory.path().to_string_lossy().to_string(),
            ),
            ("SVARTAL_ISSUER".to_string(), self.fixture["issuer"].as_str().unwrap().to_string()),
            ("SVARTAL_RELAY_URL".to_string(), self.fixture["relayUrl"].as_str().unwrap().to_string()),
        ]
        .into_iter()
        .collect();
        let now = self.fixture["nowEpochMs"].as_i64().unwrap();
        let clock = move || now;
        let browser = NoBrowser;
        let context = Context {
            config: resolve_config(&environment).unwrap(),
            http: &http,
            storage: &storage,
            browser: &browser,
            now: &clock,
        };
        let mut out: Vec<u8> = Vec::new();
        let outcome = command(&context, &mut out);
        (outcome, String::from_utf8(out).unwrap(), http)
    }
}

/// A connector for the paths that must be refused before any socket exists.
fn no_connection(_socket_url: &str) -> Result<ScriptedWs, String> {
    panic!("this close should have been refused before connecting");
}

#[test]
fn close_shell_takes_a_short_name_and_says_it_closed_the_shell() {
    let harness = Harness::new("close-shortname");
    harness.run(MACHINES_BODY, |context, out| commands::name(context, out, "web", "Primary")).0.unwrap();

    let thread_id = format!("svartal-shell:{}", harness.subject());
    let sent: Rc<RefCell<Vec<Value>>> = Rc::default();
    let recorded = sent.clone();
    let incoming =
        VecDeque::from(vec![snapshot_chunk(&[(&thread_id, "shell-env-primary")]), close_exit()]);
    let (outcome, output, http) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Shell, Some("web"), None, move |_url| {
            Ok(ScriptedWs { incoming, sent: recorded })
        })
    });
    outcome.unwrap();
    assert_eq!(output, "Closed the shell on Primary.\n");

    // The close names the one terminal it was asked about, in this person's
    // shell namespace.
    let frames = sent.borrow();
    let close = frames.iter().find(|frame| frame["tag"] == json!("terminal.close")).unwrap();
    assert_eq!(
        close["payload"],
        json!({ "threadId": thread_id, "terminalId": "shell-env-primary" })
    );

    // Closing asks for `terminal:operate` alone: there is no workspace config
    // to read, so `orchestration:read` stays out of the token.
    let form = http.last_form(&format!("{WORKSPACE_BASE}/oauth/token"));
    assert_eq!(common::form_value(&form, "scope").as_deref(), Some("terminal:operate"));
}

#[test]
fn close_claude_with_no_target_picks_the_one_reachable_workspace() {
    let harness = Harness::new("close-claude-auto");
    let thread_id = format!("svartal-claude:{}", harness.subject());
    let sent: Rc<RefCell<Vec<Value>>> = Rc::default();
    let recorded = sent.clone();
    let incoming =
        VecDeque::from(vec![snapshot_chunk(&[(&thread_id, "claude-env-primary")]), close_exit()]);
    let (outcome, output, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Claude, None, None, move |_url| {
            Ok(ScriptedWs { incoming, sent: recorded })
        })
    });
    outcome.unwrap();
    assert_eq!(output, "Closed the Claude terminal on Primary.\n");

    let frames = sent.borrow();
    let close = frames.iter().find(|frame| frame["tag"] == json!("terminal.close")).unwrap();
    assert_eq!(
        close["payload"],
        json!({ "threadId": thread_id, "terminalId": "claude-env-primary" })
    );
}

#[test]
fn nothing_running_is_an_answer_on_stdout_not_an_error() {
    let harness = Harness::new("close-nothing");
    // The person's shell is live; their Claude terminal is not, and the other
    // way round. Neither close may touch the terminal that is running.
    let shell_thread = format!("svartal-shell:{}", harness.subject());

    let sent: Rc<RefCell<Vec<Value>>> = Rc::default();
    let recorded = sent.clone();
    let incoming = VecDeque::from(vec![snapshot_chunk(&[(&shell_thread, "shell-env-primary")])]);
    let (outcome, output, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Claude, Some("Primary"), None, move |_url| {
            Ok(ScriptedWs { incoming, sent: recorded })
        })
    });
    outcome.unwrap();
    assert_eq!(output, "No Claude terminal was running on Primary.\n");
    assert!(
        !sent.borrow().iter().any(|frame| frame["tag"] == json!("terminal.close")),
        "nothing to close means no close call"
    );

    let sent: Rc<RefCell<Vec<Value>>> = Rc::default();
    let recorded = sent.clone();
    let incoming = VecDeque::from(vec![snapshot_chunk(&[])]);
    let (outcome, output, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Shell, Some("Primary"), None, move |_url| {
            Ok(ScriptedWs { incoming, sent: recorded })
        })
    });
    outcome.unwrap();
    assert_eq!(output, "No shell was running on Primary.\n");
}

#[test]
fn a_terminal_id_override_closes_that_terminal_and_no_other() {
    let harness = Harness::new("close-override");
    let thread_id = format!("svartal-shell:{}", harness.subject());
    let sent: Rc<RefCell<Vec<Value>>> = Rc::default();
    let recorded = sent.clone();
    let incoming = VecDeque::from(vec![
        snapshot_chunk(&[(&thread_id, "shell-env-primary"), (&thread_id, "shell-second")]),
        close_exit(),
    ]);
    let (outcome, output, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(
            context,
            out,
            TerminalKind::Shell,
            Some("Primary"),
            Some("shell-second"),
            move |_url| Ok(ScriptedWs { incoming, sent: recorded }),
        )
    });
    outcome.unwrap();
    assert_eq!(output, "Closed the shell on Primary.\n");

    let frames = sent.borrow();
    let close = frames.iter().find(|frame| frame["tag"] == json!("terminal.close")).unwrap();
    assert_eq!(close["payload"], json!({ "threadId": thread_id, "terminalId": "shell-second" }));
}

#[test]
fn an_ambiguous_word_is_a_question_not_a_close() {
    let harness = Harness::new("close-ambiguous");
    // `workbench` is the machine both workspaces sit on.
    let (outcome, output, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Shell, Some("workbench"), None, no_connection)
    });
    let message = outcome.unwrap_err().to_string();
    assert!(message.contains("workbench matches more than one workspace"));
    assert!(output.is_empty());
}

#[test]
fn an_unlinked_workspace_is_refused_with_the_open_verbs_sentence() {
    let harness = Harness::new("close-unlinked");
    let (outcome, _, _) = harness.run(MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Shell, Some("Second"), None, no_connection)
    });
    assert!(outcome.unwrap_err().to_string().contains("You are not linked to Second"));
}

#[test]
fn an_offline_machine_is_refused_before_any_connection() {
    let harness = Harness::new("close-offline");
    let (outcome, _, _) = harness.run(OFFLINE_MACHINES_BODY, |context, out| {
        commands::close_with(context, out, TerminalKind::Claude, Some("Primary"), None, no_connection)
    });
    assert!(outcome.unwrap_err().to_string().contains("last reported that it is offline"));
}

// -- the argument surface ----------------------------------------------------

/// These run the built `sv` itself: the sentences below come from `main.rs`,
/// which no library test can reach. Every one of them fails before any
/// configuration or network is touched.
fn sv(arguments: &[&str]) -> (bool, String, String) {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_sv"))
        .args(arguments)
        .output()
        .expect("run sv");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

#[test]
fn close_refuses_a_flag_it_does_not_take() {
    let (success, stdout, stderr) = sv(&["close", "shell", "web", "--json"]);
    assert!(!success);
    assert!(stdout.is_empty());
    assert_eq!(stderr, "sv: --json is not an option `sv close` takes.\n");
}

#[test]
fn close_without_a_kind_or_with_a_wrong_one_says_what_it_closes() {
    let (success, _, stderr) = sv(&["close"]);
    assert!(!success);
    assert_eq!(
        stderr,
        "sv: `sv close` needs to know which kind of terminal to close: `sv close shell <target>` or `sv close claude [target]`.\n"
    );

    let (success, _, stderr) = sv(&["close", "pty"]);
    assert!(!success);
    assert_eq!(
        stderr,
        "sv: `sv close pty` is not a thing sv can close. It is `sv close shell <target>` or `sv close claude [target]`.\n"
    );
}

#[test]
fn close_shell_without_a_target_is_refused_like_the_open_verb() {
    let (success, _, stderr) = sv(&["close", "shell"]);
    assert!(!success);
    assert_eq!(
        stderr,
        "sv: `sv close shell` needs the machine or workspace whose shell to close. Run `sv envs` to see them.\n"
    );
}
