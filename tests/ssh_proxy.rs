//! `sv ssh-proxy`, pinned to the frozen contract and to the TypeScript client.
//!
//! `tests/fixtures/ssh.json` was recorded by driving ivaldi's real
//! `runSshProxy` against a stubbed relay, a stubbed workspace and a WebSocket
//! double, and writing down everything that crossed a boundary: the four HTTP
//! requests of the connect chain (with each DPoP proof's claims), every
//! WebSocket frame the client sent, the server frames it was answered with,
//! what reached stdout, what `known_hosts` held afterwards, and the
//! `~/.ssh/config` block `sv ssh-setup` writes.
//!
//! These tests replay the same answers into the Rust client and require the
//! same requests and the same bytes back.
//!
//! Regenerate with:
//!   node tests/fixtures/generate-ssh.mjs tests/fixtures <ivaldi>/packages/svartal-cli

mod common;

use std::collections::VecDeque;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

use common::{TempDir, fixture};
use svartal::dpop::{DpopKey, PrivateJwk};
use svartal::rpc::TransportError;
use svartal::sshproxy::{
    self, ConfigBlockInput, FrameDecoder, InputPoll, KnownHostsChange, KnownHostsTarget,
    ProxyInput, ProxyStdio, SshOutcome, encode_frame, encode_open_frame, encode_stdin_frames,
    exit_status_for,
};
use svartal::ws::BinaryTransport;

// -- doubles ---------------------------------------------------------------

/// The bridge, as a script: each server message is delivered once the client
/// has sent the number of frames that would have prompted it.
///
/// That is the only ordering a transcript can pin. Wall-clock timing is not
/// part of the protocol, and a transport that answered on a timer would make
/// the test a race.
struct ScriptedTransport {
    sent: Vec<Vec<u8>>,
    script: VecDeque<(usize, Vec<u8>)>,
    /// Delivered after the script runs out, once.
    closed: bool,
}

impl ScriptedTransport {
    fn new(script: Vec<(usize, Vec<u8>)>) -> Self {
        Self {
            sent: Vec::new(),
            script: script.into(),
            closed: false,
        }
    }

    fn sent_hex(&self) -> Vec<String> {
        self.sent.iter().map(|frame| hex(frame)).collect()
    }
}

impl BinaryTransport for ScriptedTransport {
    fn recv(&mut self, _timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        match self.script.front() {
            Some((after, _)) if self.sent.len() >= *after => {
                let (_, message) = self.script.pop_front().expect("front exists");
                Ok(Some(message))
            }
            Some(_) => Ok(None),
            None => {
                if self.closed {
                    return Err(TransportError::Closed("the connection closed.".to_string()));
                }
                self.closed = true;
                Ok(None)
            }
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.sent.push(bytes.to_vec());
        Ok(())
    }
}

/// The local end: scripted stdin, recorded stdout.
struct ScriptedStdio {
    input: VecDeque<Vec<u8>>,
    ended: bool,
    written: Vec<Vec<u8>>,
}

impl ScriptedStdio {
    fn new(input: Vec<Vec<u8>>) -> Self {
        Self {
            input: input.into(),
            ended: false,
            written: Vec::new(),
        }
    }

    fn written_hex(&self) -> Vec<String> {
        self.written.iter().map(|chunk| hex(chunk)).collect()
    }
}

impl ProxyStdio for ScriptedStdio {
    fn take_input(&mut self) -> InputPoll {
        match self.input.pop_front() {
            Some(data) => InputPoll::Data(data),
            None if self.ended => InputPoll::None,
            None => {
                self.ended = true;
                InputPoll::Ended
            }
        }
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.written.push(bytes.to_vec());
        Ok(())
    }
}

/// The local end with a stdout nothing is reading: a real pipe whose read side
/// is closed, so the write fails the way `ssh` going away makes it fail.
struct BrokenStdout {
    pipe: std::fs::File,
}

impl BrokenStdout {
    fn new() -> Self {
        let mut ends = [0 as libc::c_int; 2];
        // SAFETY: `pipe` fills two descriptors into an array this frame owns.
        assert_eq!(unsafe { libc::pipe(ends.as_mut_ptr()) }, 0, "pipe failed");
        // SAFETY: the read end is ours and is closed exactly once.
        unsafe { libc::close(ends[0]) };
        // SAFETY: the write end is ours; `File` owns it from here.
        let pipe = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(ends[1]) };
        Self { pipe }
    }
}

impl ProxyStdio for BrokenStdout {
    fn take_input(&mut self) -> InputPoll {
        InputPoll::None
    }

    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        self.pipe.write_all(bytes)?;
        self.pipe.flush()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
        .collect()
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
        .iter()
        .map(|entry| entry.as_str().expect("string").to_string())
        .collect()
}

fn proxy_input<'a>(fixture: &'a Value, known_hosts: &'a Path, alias: &'a str) -> ProxyInput<'a> {
    ProxyInput {
        label: fixture["target"]["label"].as_str().expect("label"),
        public_key: fixture["clientPublicKey"].as_str().expect("client key"),
        client_name: Some(sshproxy::CLIENT_NAME),
        known_hosts: KnownHostsTarget {
            path: known_hosts,
            alias,
        },
        ping_interval: Duration::from_secs(3_600),
    }
}

/// Replay the recorded transcript through the Rust pump.
fn replay(fixture: &Value, directory: &TempDir) -> (ScriptedTransport, ScriptedStdio, SshOutcome) {
    let server = strings(fixture, "serverFrames");
    let stdin: Vec<Vec<u8>> = strings(fixture, "stdinChunks")
        .iter()
        .map(|hex| unhex(hex))
        .collect();
    // The recorded order: `READY` answers `OPEN`; the output and the status
    // follow the two `STDIN` frames and the `STDIN_EOF`.
    let script = vec![
        (1, unhex(&server[0])),
        (4, unhex(&server[1])),
        (4, unhex(&server[2])),
        (4, unhex(&server[3])),
    ];
    let mut transport = ScriptedTransport::new(script);
    let mut stdio = ScriptedStdio::new(stdin);
    let known_hosts = directory.path().join("known_hosts");
    let alias = fixture["alias"].as_str().expect("alias").to_string();
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(fixture, &known_hosts, &alias),
    )
    .expect("the recorded transcript is a complete connection");
    (transport, stdio, outcome)
}

// -- byte parity with the TypeScript client --------------------------------

#[test]
fn the_frames_this_client_sends_are_the_reference_bytes() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-frames");
    let (transport, _, _) = replay(&recorded, &directory);
    assert_eq!(transport.sent_hex(), strings(&recorded, "clientFrames"));
}

#[test]
fn the_bytes_this_client_writes_are_the_reference_bytes() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-stdout");
    let (_, stdio, outcome) = replay(&recorded, &directory);
    assert_eq!(stdio.written_hex(), strings(&recorded, "stdoutChunks"));
    assert_eq!(
        outcome.reason,
        recorded["outcome"]["reason"].as_str().expect("reason")
    );
    assert_eq!(
        i64::from(outcome.exit_code),
        recorded["outcome"]["exitCode"].as_i64().expect("code")
    );
    assert_eq!(
        outcome.connection_id.as_deref(),
        recorded["connectionId"].as_str()
    );
}

#[test]
fn the_host_key_lands_in_known_hosts_exactly_as_the_reference_wrote_it() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-hosts");
    replay(&recorded, &directory);
    assert_eq!(
        sshproxy::read_known_hosts(&directory.path().join("known_hosts")),
        strings(&recorded, "knownHosts")
    );
}

#[test]
fn the_config_block_is_the_reference_text() {
    let recorded = fixture("ssh.json");
    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: recorded["alias"].as_str().expect("alias"),
        target: recorded["shortname"].as_str().expect("shortname"),
        binary: "/usr/local/bin/sv",
        identity_file: "/home/person/.config/svartal/ssh/id_ed25519",
        known_hosts_file: "/home/person/.config/svartal/ssh/known_hosts",
    });
    assert_eq!(block, recorded["configBlock"].as_str().expect("block"));
}

// -- the connect chain -----------------------------------------------------

#[test]
fn the_connect_chain_is_the_reference_chain() {
    let recorded = fixture("ssh.json");
    let jwk: PrivateJwk = serde_json::from_value(recorded["privateJwk"].clone()).expect("jwk");
    let key = DpopKey::from_private_jwk(&jwk).expect("key");
    let relay = recorded["relayUrl"].as_str().expect("relay");
    let http_base = recorded["httpBaseUrl"].as_str().expect("workspace");
    let environment_id = recorded["environmentId"].as_str().expect("environment");
    let calls = recorded["httpCalls"].as_array().expect("calls").clone();

    let responses: Vec<(String, Value)> = vec![
        (
            format!("{relay}/v1/client/dpop-token"),
            json!({
                "access_token": "relay-access-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": "environment:connect",
            }),
        ),
        (
            format!("{relay}/v1/environments/{environment_id}/connect"),
            json!({
                "environmentId": environment_id,
                "endpoint": {
                    "httpBaseUrl": http_base,
                    "wsBaseUrl": recorded["wsBaseUrl"],
                    "providerKind": "cloudflare_tunnel",
                },
                "credential": "environment-credential",
                "expiresAt": "2026-08-19T12:05:00.000Z",
            }),
        ),
        (
            format!("{http_base}/oauth/token"),
            json!({
                "access_token": "workspace-access-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": "terminal:operate",
            }),
        ),
        (
            format!("{http_base}/api/auth/websocket-ticket"),
            json!({ "ticket": "ws-ticket-ssh-fixture", "expiresAt": "2026-08-19T12:05:00.000Z" }),
        ),
    ];
    let routes = responses.clone();
    let http = common::FakeTransport::new(move |request| {
        let body = routes
            .iter()
            .find(|(url, _)| *url == request.url)
            .map(|(_, body)| body.clone())
            .unwrap_or_else(|| json!({}));
        common::json_response(200, &body)
    });

    let target = svartal::target::ShellTarget {
        environment_id: environment_id.to_string(),
        label: recorded["target"]["label"]
            .as_str()
            .expect("label")
            .to_string(),
        machine_name: recorded["target"]["machineName"]
            .as_str()
            .map(str::to_string),
        linked: true,
        machine_presence: Some("unknown".to_string()),
    };

    let socket_url = sshproxy::connect_bridge(
        &http,
        &sshproxy::BridgeConnectInput {
            relay_url: relay,
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: svartal::workspace::CLI_CLIENT_METADATA,
        },
    )
    .expect("the connect chain");

    // Same four calls, in the same order, as the reference made.
    let expected: Vec<String> = calls
        .iter()
        .map(|call| call["url"].as_str().expect("url").to_string())
        .collect();
    assert_eq!(http.urls(), expected);
    // Same route, same ticket.
    assert_eq!(
        socket_url,
        recorded["socketUrl"].as_str().expect("socket url")
    );

    // `terminal:operate`, and only that: nothing on this path looks a working
    // directory up, so `orchestration:read` stays out of the token.
    let token_form = http.last_form(&format!("{http_base}/oauth/token"));
    let scope = common::form_value(&token_form, "scope").expect("a scope");
    assert_eq!(scope, "terminal:operate");
    assert!(!scope.contains("orchestration"));

    // The ticket call presents the workspace token, and its proof is bound to
    // it — the reference's proof claims carry `ath` on exactly that call.
    let ticket_headers = http.last_headers(&format!("{http_base}/api/auth/websocket-ticket"));
    let authorization = ticket_headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value.clone())
        .expect("an authorization header");
    assert_eq!(authorization, "DPoP workspace-access-token");
    let reference_ticket_call = calls
        .iter()
        .find(|call| {
            call["url"].as_str() == Some(&format!("{http_base}/api/auth/websocket-ticket"))
        })
        .expect("the reference took a ticket");
    assert!(reference_ticket_call["dpopClaims"]["ath"].is_string());
}

// -- the pump's own rules --------------------------------------------------

#[test]
fn bytes_that_are_not_utf8_survive_both_directions() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-binary");
    // A lone continuation byte, a bare 0xff, a NUL: an SSH binary packet looks
    // like this, and a client that decoded it would corrupt the transport.
    let typed = vec![0x00u8, 0xff, 0x80, 0xfe, 0x41, 0x0a];
    let from_server = vec![0x80u8, 0x00, 0xc3, 0x28, 0xff];
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut stdout_frame = encode_frame(0x82, &from_server);
    stdout_frame.extend_from_slice(&encode_frame(
        0x83,
        json!({ "reason": "sshd_exited", "exitCode": 0 })
            .to_string()
            .as_bytes(),
    ));

    let mut transport = ScriptedTransport::new(vec![(1, ready), (3, stdout_frame)]);
    let mut stdio = ScriptedStdio::new(vec![typed.clone()]);
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("a complete connection");

    assert_eq!(outcome.exit_code, 0);
    assert_eq!(transport.sent[1], encode_frame(0x02, &typed));
    assert_eq!(stdio.written, vec![from_server]);
}

#[test]
fn nothing_but_payload_bytes_reaches_stdout() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-purity");
    let payload = b"SSH-2.0-OpenSSH_9.2p1\r\n".to_vec();
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut noise = encode_frame(0x82, &payload);
    // A `PONG` and an empty `STDOUT` are frames a client sees all the time;
    // neither may put a single byte on stdout.
    noise.extend_from_slice(&encode_frame(0x85, &[]));
    noise.extend_from_slice(&encode_frame(0x82, &[]));
    // An unknown type: the framing is intact, so it is ignored rather than
    // treated as output.
    noise.extend_from_slice(&encode_frame(0x8f, b"not output"));
    noise.extend_from_slice(&encode_frame(
        0x83,
        json!({ "reason": "sshd_exited", "exitCode": 0 })
            .to_string()
            .as_bytes(),
    ));

    let mut transport = ScriptedTransport::new(vec![(1, ready), (2, noise)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("a complete connection");

    assert_eq!(stdio.written, vec![payload]);
}

#[test]
fn local_input_ending_is_a_half_close() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-eof");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let tail = b"output after eof".to_vec();
    let mut after_eof = encode_frame(0x82, &tail);
    after_eof.extend_from_slice(&encode_frame(
        0x83,
        json!({ "reason": "sshd_exited", "exitCode": 0 })
            .to_string()
            .as_bytes(),
    ));

    let mut transport = ScriptedTransport::new(vec![(1, ready), (3, after_eof)]);
    let mut stdio = ScriptedStdio::new(vec![b"last input".to_vec()]);
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("a complete connection");

    assert_eq!(transport.sent[2], encode_frame(0x03, &[]));
    // The connection kept running after the half-close: the output that
    // followed it still arrived, and the status is the sshd's own.
    assert_eq!(stdio.written, vec![tail]);
    assert_eq!(outcome.exit_code, 0);
}

#[test]
fn a_socket_that_dies_without_an_exit_frame_ends_non_zero() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-dead");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut transport = ScriptedTransport::new(vec![(1, ready)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("an ended connection is an answer");
    assert_ne!(outcome.exit_code, 0);
}

#[test]
fn an_exit_that_arrives_instead_of_ready_is_still_the_answer() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-spawn-failed");
    // `spawn_failed`: the workspace could not start an sshd at all, so there is
    // no `READY` and never will be.
    let exit = encode_frame(
        0x83,
        json!({ "reason": "spawn_failed", "exitCode": null })
            .to_string()
            .as_bytes(),
    );
    let mut transport = ScriptedTransport::new(vec![(1, exit)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("an ended connection is an answer");
    assert_eq!(outcome.reason, "spawn_failed");
    assert_eq!(outcome.exit_code, 1);
    assert_eq!(outcome.connection_id, None);
}

#[test]
fn output_before_ready_is_a_protocol_error() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-early");
    let early = encode_frame(0x82, b"too early");
    let mut transport = ScriptedTransport::new(vec![(1, early)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let error = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect_err("a STDOUT frame before READY breaks the protocol");
    assert!(error.to_string().contains("before READY"), "{error}");
}

#[test]
fn the_exit_status_is_the_documents_status() {
    assert_eq!(exit_status_for(Some(0)), 0);
    assert_eq!(exit_status_for(Some(7)), 7);
    assert_eq!(exit_status_for(None), 1);
    assert_eq!(exit_status_for(Some(999)), 1);
    assert_eq!(exit_status_for(Some(-1)), 1);
}

/// Doc §8.5: the status the far end stated is the status, whatever the reason
/// beside it says. A `disconnected` that carries `exitCode: 0` is a command
/// that succeeded and a connection that then went away, and exiting non-zero
/// would tell `ssh` the command failed.
#[test]
fn a_stated_status_outranks_the_reason_beside_it() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-reason");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let exit = encode_frame(
        0x83,
        json!({ "reason": "disconnected", "exitCode": 0 })
            .to_string()
            .as_bytes(),
    );

    let mut transport = ScriptedTransport::new(vec![(1, ready), (2, exit)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("a complete connection");
    assert_eq!(outcome.reason, "disconnected");
    assert_eq!(outcome.exit_code, 0);
}

/// stdin and stdout are pipes from `ssh`, not a terminal (doc §8.6).
#[test]
fn the_proxy_never_touches_terminal_modes() {
    // The guard `sv shell` uses is a no-op off a terminal, which is what the
    // proxy always runs on.
    let raw = svartal::terminal::RawMode::enter();
    assert!(!raw.interactive());
    drop(raw);
    // And the proxy does not reach for it at all: nothing in the module names
    // raw mode, the window size or `SIGWINCH`.
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/sshproxy.rs"))
        .expect("the module source");
    // Comments are where the rule is written down, so only code is scanned.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["RawMode", "SIGWINCH", "terminal_size", "TIOCGWINSZ"] {
        assert!(
            !code.contains(forbidden),
            "sshproxy.rs must not use {forbidden}"
        );
    }
}

// -- the codec -------------------------------------------------------------

#[test]
fn a_frame_split_across_messages_is_reassembled() {
    let frame = encode_frame(0x82, b"split across messages");
    let mut decoder = FrameDecoder::new();
    let mut frames = Vec::new();
    // One byte at a time through the header, then the payload in two pieces.
    for index in 0..5 {
        frames.extend(
            decoder
                .push(&frame[index..index + 1])
                .expect("intact framing"),
        );
    }
    assert!(frames.is_empty());
    frames.extend(decoder.push(&frame[5..9]).expect("intact framing"));
    assert!(frames.is_empty());
    frames.extend(decoder.push(&frame[9..]).expect("intact framing"));
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, 0x82);
    assert_eq!(frames[0].payload, b"split across messages");
    assert_eq!(decoder.buffered(), 0);
}

#[test]
fn several_frames_in_one_message_are_all_decoded() {
    let mut message = encode_frame(0x81, b"{}");
    message.extend_from_slice(&encode_frame(0x82, b"one"));
    message.extend_from_slice(&encode_frame(0x85, &[]));
    let mut decoder = FrameDecoder::new();
    let frames = decoder.push(&message).expect("intact framing");
    assert_eq!(
        frames.iter().map(|frame| frame.kind).collect::<Vec<_>>(),
        vec![0x81, 0x82, 0x85]
    );
    assert_eq!(frames[2].payload.len(), 0);
}

#[test]
fn a_length_past_the_ceiling_is_a_protocol_break() {
    let mut header = vec![0x82u8];
    header.extend_from_slice(&(sshproxy::MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes());
    let mut decoder = FrameDecoder::new();
    // The break is recorded, and every push after it is refused.
    assert!(decoder.push(&header).expect("nothing completed").is_empty());
    assert!(decoder.broken().is_some());
    assert!(decoder.push(b"anything at all").is_err());
}

/// A message that carries a good frame and then rubbish still delivers the
/// good frame: the far end's own `EXIT` is the connection's answer, and losing
/// it to the bytes that followed it would turn a clean status into a guess.
#[test]
fn the_frames_before_a_broken_header_are_still_delivered() {
    let mut message = encode_frame(
        0x83,
        json!({ "reason": "sshd_exited", "exitCode": 3 })
            .to_string()
            .as_bytes(),
    );
    let mut garbage = vec![0x82u8];
    garbage.extend_from_slice(&(sshproxy::MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes());
    message.extend_from_slice(&garbage);

    let mut decoder = FrameDecoder::new();
    let frames = decoder.push(&message).expect("the EXIT was complete");
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].kind, 0x83);
    assert!(decoder.broken().is_some());

    // And through the pump: the status is the `EXIT`'s, not a protocol error.
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-broken-tail");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut transport = ScriptedTransport::new(vec![(1, ready), (2, message)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("the EXIT ended the connection");
    assert_eq!(outcome.reason, "sshd_exited");
    assert_eq!(outcome.exit_code, 3);
}

/// The same rubbish with nothing complete before it is what it looks like: a
/// protocol error, on stderr, with a status.
#[test]
fn a_broken_header_with_nothing_before_it_ends_the_connection() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-broken");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut garbage = vec![0x82u8];
    garbage.extend_from_slice(&(sshproxy::MAX_FRAME_PAYLOAD as u32 + 1).to_be_bytes());

    let mut transport = ScriptedTransport::new(vec![(1, ready), (2, garbage)]);
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let error = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect_err("a frame past the ceiling breaks the protocol");
    assert!(error.to_string().contains("payload ceiling"), "{error}");
}

#[test]
fn a_write_larger_than_the_ceiling_is_split() {
    let data: Vec<u8> = (0..sshproxy::MAX_FRAME_PAYLOAD + 17)
        .map(|index| (index % 256) as u8)
        .collect();
    let frames = encode_stdin_frames(&data);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0].len(), 5 + sshproxy::MAX_FRAME_PAYLOAD);
    assert_eq!(frames[1].len(), 5 + 17);
    let mut decoder = FrameDecoder::new();
    let mut decoded = Vec::new();
    for frame in frames {
        for frame in decoder.push(&frame).expect("intact framing") {
            decoded.extend_from_slice(&frame.payload);
        }
    }
    assert_eq!(decoded, data);
}

#[test]
fn the_open_frame_carries_the_version_and_the_key() {
    let frame = encode_open_frame("ssh-ed25519 AAAA person@laptop", Some("sv"));
    assert_eq!(frame[0], 0x01);
    let payload: Value = serde_json::from_slice(&frame[5..]).expect("json");
    assert_eq!(payload["version"], json!(1));
    assert_eq!(
        payload["publicKey"],
        json!("ssh-ed25519 AAAA person@laptop")
    );
    assert_eq!(payload["clientName"], json!("sv"));
    // A client that sends no name sends no field, rather than an empty one.
    let anonymous = encode_open_frame("ssh-ed25519 AAAA person@laptop", None);
    let payload: Value = serde_json::from_slice(&anonymous[5..]).expect("json");
    assert!(payload.get("clientName").is_none());
}

// -- the local ssh files ---------------------------------------------------

const HOST_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostKeyForTests svartal-workspace";
const OTHER_HOST_KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRotatedHostKey svartal-workspace";

#[test]
fn an_alias_is_the_name_a_person_typed() {
    assert_eq!(sshproxy::host_alias("web"), "svartal-web");
    assert_eq!(sshproxy::host_alias(" Web "), "svartal-web");
    assert_eq!(sshproxy::host_alias("env-9f3c"), "svartal-env-9f3c");
    assert_eq!(sshproxy::host_alias("My Box"), "svartal-my-box");
    assert_eq!(
        sshproxy::host_alias("weird/id with spaces"),
        "svartal-weird-id-with-spaces"
    );
    assert_eq!(sshproxy::host_alias("***"), "svartal-workspace");
}

/// `READY.hostPublicKey` goes into `known_hosts`, and `known_hosts` is a file
/// `ssh` trusts line by line. A value carrying a newline would let the far end
/// write entries for hosts it has nothing to do with, so it is checked before
/// it is used for anything.
#[test]
fn a_host_key_that_is_not_one_line_ends_the_connection() {
    let injected = format!("{HOST_KEY}\ngithub.com {OTHER_HOST_KEY}");
    for payload in [
        injected.as_str(),
        &format!("{HOST_KEY}\rgithub.com {OTHER_HOST_KEY}"),
        "ssh-ed25519\tAAAAkey",
        "ssh-ed25519",
        "   ",
        // Three is a key with a comment; four is not a key line.
        &format!("{HOST_KEY} and more"),
    ] {
        let ready = json!({ "connectionId": "c1", "hostPublicKey": payload }).to_string();
        let error = sshproxy::decode_ready(ready.as_bytes())
            .expect_err(&format!("{payload:?} is not one host key line"));
        assert!(
            error.contains("hostPublicKey"),
            "{payload:?} was refused with {error}"
        );
    }
    // The good one still passes, comment and all.
    assert_eq!(
        sshproxy::decode_ready(
            json!({ "connectionId": "c1", "hostPublicKey": format!("  {HOST_KEY}  ") })
                .to_string()
                .as_bytes()
        )
        .expect("a host key line")
        .host_public_key,
        HOST_KEY
    );
}

/// The same check on the way in to the file, because the write is public and a
/// second caller must not be able to walk past the frame's check.
#[test]
fn known_hosts_refuses_a_key_that_would_write_two_lines() {
    let directory = TempDir::new("known-hosts-injection");
    let path = directory.path().join("known_hosts");
    sshproxy::write_known_host(
        &path,
        "svartal-web",
        &format!("{HOST_KEY}\ngithub.com {HOST_KEY}"),
    )
    .expect_err("a key with a newline in it");
    assert!(sshproxy::read_known_hosts(&path).is_empty());

    // And a good one writes exactly one line.
    sshproxy::write_known_host(&path, "svartal-web", HOST_KEY).expect("write");
    let raw = std::fs::read_to_string(&path).expect("read");
    assert_eq!(raw, format!("svartal-web {HOST_KEY}\n"));
}

#[test]
fn known_hosts_keeps_one_entry_per_alias() {
    let directory = TempDir::new("known-hosts");
    let path = directory.path().join("known_hosts");
    assert_eq!(
        sshproxy::write_known_host(&path, "svartal-web", HOST_KEY).expect("write"),
        KnownHostsChange::Added
    );
    assert_eq!(
        sshproxy::write_known_host(&path, "svartal-web", HOST_KEY).expect("write"),
        KnownHostsChange::Unchanged
    );
    assert_eq!(
        sshproxy::write_known_host(&path, "svartal-web", OTHER_HOST_KEY).expect("write"),
        KnownHostsChange::Replaced
    );
    assert_eq!(
        sshproxy::read_known_hosts(&path),
        vec![format!("svartal-web {OTHER_HOST_KEY}")]
    );
    assert_eq!(
        sshproxy::remove_known_host(&path, "svartal-web").expect("remove"),
        KnownHostsChange::Removed
    );
    assert!(sshproxy::read_known_hosts(&path).is_empty());
}

#[test]
fn known_hosts_leaves_every_other_host_alone() {
    let directory = TempDir::new("known-hosts-others");
    let path = directory.path().join("known_hosts");
    std::fs::write(
        &path,
        format!("github.com {HOST_KEY}\nsvartal-box {HOST_KEY}\n"),
    )
    .expect("seed");
    sshproxy::write_known_host(&path, "svartal-web", HOST_KEY).expect("write");
    sshproxy::remove_known_host(&path, "svartal-box").expect("remove");
    assert_eq!(
        sshproxy::read_known_hosts(&path),
        vec![
            format!("github.com {HOST_KEY}"),
            format!("svartal-web {HOST_KEY}")
        ]
    );
}

/// Two editor windows are two `ProxyCommand` processes, and this is the case
/// the lock exists for: eight writers, one file, no lost entry.
#[test]
fn known_hosts_loses_nothing_under_concurrent_writers() {
    let directory = TempDir::new("known-hosts-race");
    let path = directory.path().join("known_hosts");
    std::thread::scope(|scope| {
        for index in 0..8 {
            let path = path.clone();
            scope.spawn(move || {
                sshproxy::write_known_host(&path, &format!("svartal-{index}"), HOST_KEY)
                    .expect("write");
            });
        }
    });
    let entries = sshproxy::read_known_hosts(&path);
    assert_eq!(entries.len(), 8, "{entries:?}");
    for index in 0..8 {
        assert!(
            entries.contains(&format!("svartal-{index} {HOST_KEY}")),
            "{entries:?}"
        );
    }
}

#[test]
fn a_lock_its_holder_died_with_is_taken_over() {
    let directory = TempDir::new("known-hosts-stale");
    let path = directory.path().join("known_hosts");
    let lock = directory.path().join("known_hosts.lock");
    std::fs::write(&lock, "another-process").expect("lock");
    // A lock file with an ancient mtime is a process that died holding it.
    let ancient = std::time::SystemTime::now() - Duration::from_secs(60);
    filetime_set(&lock, ancient);
    assert_eq!(
        sshproxy::write_known_host(&path, "svartal-web", HOST_KEY).expect("write"),
        KnownHostsChange::Added
    );
    // Taken over, used, and given back.
    assert!(!lock.exists());
}

/// A lock that never frees means the edit is skipped, not forced: writing
/// anyway is a read-modify-write racing whoever holds it, which is how an
/// entry gets lost. The connection itself is unaffected — the block asks for
/// `StrictHostKeyChecking accept-new` — so this is the cheaper miss.
#[test]
fn a_lock_that_never_frees_leaves_the_file_alone() {
    let directory = TempDir::new("known-hosts-held");
    let path = directory.path().join("known_hosts");
    let lock = directory.path().join("known_hosts.lock");
    std::fs::write(&lock, "another-process").expect("lock");
    std::fs::write(&path, format!("svartal-web {OTHER_HOST_KEY}\n")).expect("seed");

    assert_eq!(
        sshproxy::write_known_host_within(
            &path,
            "svartal-web",
            HOST_KEY,
            Duration::from_millis(50)
        )
        .expect("a skipped edit is not a failure"),
        KnownHostsChange::Unchanged
    );
    // Untouched: the entry that was there is the entry that is there, and the
    // lock is still the other process's.
    assert_eq!(
        sshproxy::read_known_hosts(&path),
        vec![format!("svartal-web {OTHER_HOST_KEY}")]
    );
    assert_eq!(
        std::fs::read_to_string(&lock).expect("read"),
        "another-process"
    );
}

/// The stale-takeover race, from the other side. This process's own lock can
/// be taken over while it holds it — that is what `LOCK_STALE` is for — and
/// from that moment the file belongs to whoever took it. Releasing has to
/// notice, or it deletes a lock a second process is holding and lets a third
/// one in on top of both.
#[test]
fn releasing_a_lock_someone_else_took_over_leaves_it_alone() {
    let directory = TempDir::new("known-hosts-token");
    let lock = directory.path().join("known_hosts.lock");

    let held = sshproxy::KnownHostsLock::take(&lock, Duration::from_millis(50))
        .expect("the lock is free")
        .expect("taken");
    // The file says which process holds it.
    let token = std::fs::read_to_string(&lock).expect("read");
    assert!(
        token.starts_with(&format!("{}-", std::process::id())),
        "{token}"
    );
    // Nobody else can take it while it is held and fresh.
    assert!(
        sshproxy::KnownHostsLock::take(&lock, Duration::from_millis(50))
            .expect("no error")
            .is_none()
    );
    drop(held);
    assert!(!lock.exists());

    // Now the other order: taken over while this process held it.
    let held = sshproxy::KnownHostsLock::take(&lock, Duration::from_millis(50))
        .expect("the lock is free")
        .expect("taken");
    std::fs::write(&lock, "a-second-process").expect("take over");
    drop(held);
    assert_eq!(
        std::fs::read_to_string(&lock).expect("read"),
        "a-second-process"
    );
}

/// `utimes` on a path, without a crate: the test needs one mtime in the past.
fn filetime_set(path: &Path, when: std::time::SystemTime) {
    let seconds = when
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs() as libc::time_t;
    let times = [
        libc::timeval {
            tv_sec: seconds,
            tv_usec: 0,
        },
        libc::timeval {
            tv_sec: seconds,
            tv_usec: 0,
        },
    ];
    let raw = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path");
    // SAFETY: both pointers are owned by this frame for the whole call.
    let result = unsafe { libc::utimes(raw.as_ptr(), times.as_ptr()) };
    assert_eq!(result, 0, "utimes failed");
}

#[test]
fn the_config_block_is_marker_guarded() {
    let directory = TempDir::new("ssh-config");
    let path = directory.path().join("config");
    let block = |binary: &str| {
        sshproxy::ssh_config_block(&ConfigBlockInput {
            alias: "svartal-web",
            target: "web",
            binary,
            identity_file: "/keys/id_ed25519",
            known_hosts_file: "/keys/known_hosts",
        })
    };

    std::fs::write(&path, "Host build\n  HostName build.example.com\n").expect("seed");
    assert_eq!(
        sshproxy::apply_ssh_config_block(&path, "svartal-web", &block("/usr/local/bin/sv"))
            .expect("apply"),
        sshproxy::ConfigChange::Added
    );
    assert_eq!(
        sshproxy::apply_ssh_config_block(&path, "svartal-web", &block("/usr/local/bin/sv"))
            .expect("apply"),
        sshproxy::ConfigChange::Unchanged
    );
    assert_eq!(
        sshproxy::apply_ssh_config_block(&path, "svartal-web", &block("/opt/sv")).expect("apply"),
        sshproxy::ConfigChange::Replaced
    );

    let written = std::fs::read_to_string(&path).expect("read");
    assert!(written.contains("Host build"), "{written}");
    assert!(
        written.contains("ProxyCommand /opt/sv ssh-proxy web"),
        "{written}"
    );
    assert!(!written.contains("/usr/local/bin/sv"), "{written}");
    // One block, not two.
    assert_eq!(
        written
            .matches("# >>> sv ssh-setup svartal-web >>>")
            .count(),
        1
    );
}

#[test]
fn a_config_file_is_created_owner_only() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = TempDir::new("ssh-config-new");
    let path = directory.path().join(".ssh").join("config");
    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-web",
        target: "web",
        binary: "sv",
        identity_file: "/keys/id_ed25519",
        known_hosts_file: "/keys/known_hosts",
    });
    assert_eq!(
        sshproxy::apply_ssh_config_block(&path, "svartal-web", &block).expect("apply"),
        sshproxy::ConfigChange::Created
    );
    assert_eq!(
        std::fs::read_to_string(&path).expect("read"),
        format!("{block}\n")
    );
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
        0o600
    );
}

/// A `~/.ssh/config` that is a symlink into a dotfiles checkout is an ordinary
/// thing to have. The block goes into the file the link points at, and the link
/// is still a link afterwards — writing a new file and renaming it over the top
/// would silently take the file out of the person's repository.
#[test]
fn a_symlinked_config_is_followed_rather_than_replaced() {
    let directory = TempDir::new("ssh-config-symlink");
    let checkout = directory.path().join("dotfiles");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let real = checkout.join("ssh_config");
    std::fs::write(&real, "Host build\n  HostName build.example.com\n").expect("seed");
    let link = directory.path().join("config");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-web",
        target: "web",
        binary: "sv",
        identity_file: "/keys/id_ed25519",
        known_hosts_file: "/keys/known_hosts",
    });
    assert_eq!(
        sshproxy::apply_ssh_config_block(&link, "svartal-web", &block).expect("apply"),
        sshproxy::ConfigChange::Added
    );

    let written = std::fs::read_to_string(&real).expect("the target holds the block");
    assert!(written.contains("Host svartal-web"), "{written}");
    assert!(written.contains("Host build"), "{written}");
    assert!(
        std::fs::symlink_metadata(&link)
            .expect("stat")
            .file_type()
            .is_symlink(),
        "the link is still a link"
    );
}

/// The file is the person's, so its mode is theirs too. A `0644` config is
/// unusual and not this CLI's business; only a file it creates is `0600`.
#[test]
fn an_existing_config_keeps_the_mode_it_had() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = TempDir::new("ssh-config-mode");
    let path = directory.path().join("config");
    std::fs::write(&path, "Host build\n").expect("seed");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-web",
        target: "web",
        binary: "sv",
        identity_file: "/keys/id_ed25519",
        known_hosts_file: "/keys/known_hosts",
    });
    sshproxy::apply_ssh_config_block(&path, "svartal-web", &block).expect("apply");
    assert_eq!(
        std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
        0o644
    );
}

/// And a `~/.ssh` that is itself a symlink is a directory like any other.
#[test]
fn a_symlinked_ssh_directory_is_written_into() {
    let directory = TempDir::new("ssh-config-linked-dir");
    let real = directory.path().join("dotfiles-ssh");
    std::fs::create_dir_all(&real).expect("directory");
    let linked = directory.path().join(".ssh");
    std::os::unix::fs::symlink(&real, &linked).expect("symlink");

    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-web",
        target: "web",
        binary: "sv",
        identity_file: "/keys/id_ed25519",
        known_hosts_file: "/keys/known_hosts",
    });
    assert_eq!(
        sshproxy::apply_ssh_config_block(&linked.join("config"), "svartal-web", &block)
            .expect("apply"),
        sshproxy::ConfigChange::Created
    );
    assert!(real.join("config").exists());
}

#[test]
fn a_path_with_a_space_is_quoted() {
    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-web",
        target: "web",
        binary: "/Applications/My Tools/sv",
        identity_file: "/home/a b/id_ed25519",
        known_hosts_file: "/home/a b/known_hosts",
    });
    assert!(
        block.contains("ProxyCommand \"/Applications/My Tools/sv\" ssh-proxy web"),
        "{block}"
    );
    assert!(
        block.contains("IdentityFile \"/home/a b/id_ed25519\""),
        "{block}"
    );
}

#[test]
fn the_client_key_is_minted_once_and_never_again() {
    let directory = TempDir::new("ssh-key");
    let first = sshproxy::ensure_client_key(directory.path()).expect("mint");
    assert!(first.created);
    assert!(first.public_key.starts_with("ssh-ed25519 "));
    let minted = std::fs::read(&first.private_key_path).expect("read");

    let second = sshproxy::ensure_client_key(directory.path()).expect("read back");
    assert!(!second.created);
    assert_eq!(second.public_key, first.public_key);
    assert_eq!(
        std::fs::read(&first.private_key_path).expect("read"),
        minted
    );

    // The public half can be derived; the private one is never replaced.
    std::fs::remove_file(&first.public_key_path).expect("remove");
    let third = sshproxy::ensure_client_key(directory.path()).expect("derive");
    assert!(!third.created);
    assert_eq!(
        third
            .public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>(),
        first
            .public_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        std::fs::read(&first.private_key_path).expect("read"),
        minted
    );
}

#[test]
fn ssh_setup_writes_the_key_and_the_block() {
    let state = TempDir::new("ssh-setup-state");
    let home = TempDir::new("ssh-setup-home");
    let config_path = home.path().join("config");
    let outcome = sshproxy::run_ssh_setup(&sshproxy::SetupInput {
        state_directory: state.path(),
        target: "web",
        binary: "/usr/local/bin/sv",
        ssh_config_path: &config_path,
        print: false,
        reset_hosts: false,
    })
    .expect("setup");

    assert_eq!(outcome.alias, "svartal-web");
    assert_eq!(outcome.config, Some(sshproxy::ConfigChange::Created));
    assert!(outcome.key.created);
    let written = std::fs::read_to_string(&config_path).expect("read");
    assert!(written.contains("Host svartal-web"), "{written}");
    assert!(
        written.contains(&format!(
            "UserKnownHostsFile {}",
            sshproxy::known_hosts_path(state.path()).display()
        )),
        "{written}"
    );
    // The `ProxyCommand` carries the word that resolves, verbatim.
    assert!(
        written.contains("ProxyCommand /usr/local/bin/sv ssh-proxy web"),
        "{written}"
    );
    // And the sentence names what was written: the file, the host, the target.
    assert_eq!(
        sshproxy::describe_ssh_setup(&outcome),
        vec![
            format!(
                "Made an ssh key for this machine: {}.",
                sshproxy::client_key_path(state.path()).display()
            ),
            format!(
                "Wrote {}. `ssh svartal-web` reaches web.",
                config_path.display()
            ),
        ]
    );
}

#[test]
fn ssh_setup_print_writes_nothing() {
    let state = TempDir::new("ssh-setup-print-state");
    let home = TempDir::new("ssh-setup-print-home");
    let config_path = home.path().join("config");
    let outcome = sshproxy::run_ssh_setup(&sshproxy::SetupInput {
        state_directory: state.path(),
        target: "web",
        binary: "/usr/local/bin/sv",
        ssh_config_path: &config_path,
        print: true,
        reset_hosts: false,
    })
    .expect("setup");

    assert_eq!(outcome.config, None);
    assert!(!config_path.exists());
    assert!(outcome.block.contains("Host svartal-web"));
    // The key is still ensured: `--print` opts out of writing the config, not
    // out of having something to connect with.
    assert!(sshproxy::client_key_path(state.path()).exists());
}

#[test]
fn ssh_setup_reset_hosts_forgets_only_this_alias() {
    let state = TempDir::new("ssh-setup-reset-state");
    let home = TempDir::new("ssh-setup-reset-home");
    let config_path = home.path().join("config");
    let hosts = sshproxy::known_hosts_path(state.path());
    sshproxy::write_known_host(&hosts, "svartal-web", HOST_KEY).expect("write");
    sshproxy::write_known_host(&hosts, "svartal-box", HOST_KEY).expect("write");

    let outcome = sshproxy::run_ssh_setup(&sshproxy::SetupInput {
        state_directory: state.path(),
        target: "web",
        binary: "sv",
        ssh_config_path: &config_path,
        print: false,
        reset_hosts: true,
    })
    .expect("setup");

    assert_eq!(outcome.hosts, Some(KnownHostsChange::Removed));
    assert_eq!(
        sshproxy::read_known_hosts(&hosts),
        vec![format!("svartal-box {HOST_KEY}")]
    );
}

// -- the word the ProxyCommand carries -------------------------------------

/// One machine, one workspace, and a display name nobody could resolve: a
/// label with a space and a capital in it.
fn spaced_machines() -> Value {
    json!({
        "data": [{
            "id": "machine-1",
            "name": "workbench",
            "origin": "donated",
            "lifecycleState": "open",
            "presence": "online",
            "lastSeenAt": null,
            "environments": [
                { "id": "row-1", "environmentId": "env-9f3c", "label": "My Box", "kind": "personal", "lifecycleState": "active" },
            ],
        }],
    })
}

fn spaced_links() -> Value {
    json!({
        "environments": [{
            "environmentId": "env-9f3c",
            "label": "My Box",
            "endpoint": {
                "httpBaseUrl": "https://workspace.example.test",
                "wsBaseUrl": "wss://workspace.example.test/ws",
                "providerKind": "cloudflare_tunnel",
            },
            "linkedAt": "2026-08-01T10:00:00Z",
        }],
    })
}

fn spaced_view() -> svartal::view::MachinesView {
    let machines: Vec<svartal::api::Machine> =
        serde_json::from_value(spaced_machines()["data"].clone()).expect("machines");
    let links: Vec<svartal::api::LinkRecord> =
        serde_json::from_value(spaced_links()["environments"].clone()).expect("links");
    svartal::view::build_machines_view(&machines, &links)
}

/// Run `sv ssh-setup <target>` against that machine, in a throwaway home, and
/// hand back what landed in `~/.ssh/config`.
fn run_ssh_setup_command(
    tag: &str,
    target: &str,
    names: &svartal::shortnames::Shortnames,
) -> String {
    let recorded = fixture("oidc.json");
    let state = TempDir::new(&format!("{tag}-state"));
    let home = TempDir::new(&format!("{tag}-home"));
    svartal::shortnames::write_shortnames(state.path(), names).expect("names");

    let issuer = recorded["issuer"].as_str().expect("issuer").to_string();
    let relay = recorded["relayUrl"].as_str().expect("relay").to_string();
    let routed = recorded.clone();
    let http = common::FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return common::json_response(200, &routed["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return common::json_response(200, &routed["jwks"]);
        }
        if url == format!("{issuer}/api/v1/client/machines") {
            return common::json_response(200, &spaced_machines());
        }
        if url == format!("{relay}/v1/environments") {
            return common::json_response(200, &spaced_links());
        }
        common::json_response(404, &json!({ "error": "unexpected" }))
    });

    let storage =
        svartal::store::MemoryTokenStorage::with_value(&recorded["storedTokens"].to_string());
    let environment: svartal::config::Environment = [
        (
            "HOME".to_string(),
            home.path().to_string_lossy().to_string(),
        ),
        (
            "SVARTAL_CONFIG_DIR".to_string(),
            state.path().to_string_lossy().to_string(),
        ),
        (
            "SVARTAL_ISSUER".to_string(),
            recorded["issuer"].as_str().expect("issuer").to_string(),
        ),
        (
            "SVARTAL_RELAY_URL".to_string(),
            recorded["relayUrl"].as_str().expect("relay").to_string(),
        ),
    ]
    .into_iter()
    .collect();
    let now = recorded["nowEpochMs"].as_i64().expect("now");
    let clock = move || now;
    let browser = svartal::browser::NoBrowser;
    let context = svartal::commands::Context {
        config: svartal::config::resolve_config(&environment).expect("config"),
        http: &http,
        storage: &storage,
        browser: &browser,
        now: &clock,
    };

    let mut out: Vec<u8> = Vec::new();
    svartal::commands::ssh_setup(&context, &mut out, &environment, target, false, false)
        .expect("ssh-setup");
    std::fs::read_to_string(home.path().join(".ssh").join("config")).expect("the block")
}

/// The word in the `ProxyCommand` is handed straight back to `sv ssh-proxy`
/// with no other context, so it has to resolve on its own. A sanitized display
/// name does not: `my-box` is not this workspace's id, its short name, or its
/// label, and `ssh svartal-my-box` would have failed at the first byte.
#[test]
fn a_target_with_no_short_name_gets_a_proxy_command_that_resolves() {
    let block = run_ssh_setup_command(
        "ssh-setup-spaced",
        "My Box",
        &svartal::shortnames::Shortnames::new(),
    );
    let token = proxy_command_target(&block);
    assert_eq!(token, "env-9f3c");
    assert!(block.contains("Host svartal-env-9f3c"), "{block}");

    // The claim, checked against the machinery that has to honour it.
    let view = spaced_view();
    let names = svartal::shortnames::Shortnames::new();
    assert_eq!(
        svartal::target::select_shell_target(&view, &names, &token)
            .expect("the written token resolves")
            .environment_id,
        "env-9f3c"
    );
    // And the token this used to write does not.
    assert!(
        svartal::target::select_shell_target(&view, &names, &sshproxy::alias_token("My Box"))
            .is_err(),
        "a sanitized display name is not a target"
    );
}

/// With a short name recorded, that is the word: the person chose it, it
/// resolves, and it is what makes the host alias readable.
#[test]
fn a_recorded_short_name_is_the_word_the_proxy_command_carries() {
    let mut names = svartal::shortnames::Shortnames::new();
    names.assign("box", "env-9f3c").expect("name");
    let block = run_ssh_setup_command("ssh-setup-named", "My Box", &names);
    assert_eq!(proxy_command_target(&block), "box");
    assert!(block.contains("Host svartal-box"), "{block}");
    assert_eq!(
        svartal::target::select_shell_target(&spaced_view(), &names, "box")
            .expect("the written token resolves")
            .environment_id,
        "env-9f3c"
    );
}

/// The `<target>` out of the block's `ProxyCommand` line.
fn proxy_command_target(block: &str) -> String {
    block
        .lines()
        .find_map(|line| line.trim().strip_prefix("ProxyCommand "))
        .and_then(|line| line.split(" ssh-proxy ").nth(1))
        .map(|target| target.trim().trim_matches('"').to_string())
        .unwrap_or_else(|| panic!("no ProxyCommand line in {block}"))
}

#[test]
fn the_ssh_config_path_comes_from_the_home_directory() {
    let mut environment = svartal::config::Environment::new();
    environment.insert("HOME".to_string(), "/home/person".to_string());
    assert_eq!(
        sshproxy::default_ssh_config_path(&environment).expect("path"),
        Path::new("/home/person/.ssh/config")
    );
    let empty = svartal::config::Environment::new();
    assert!(sshproxy::default_ssh_config_path(&empty).is_err());
}

/// The `ProxyCommand` names the `sv` this command was *invoked* as, symlinks
/// and all. Resolving them would bake a Homebrew Cellar path — one that the
/// next `brew upgrade` deletes — into a file that outlives the upgrade.
#[test]
fn the_proxy_command_keeps_the_binary_the_person_invoked() {
    let cwd = Path::new("/home/person/work");
    // On `PATH`: written as it was typed, because `ssh` finds it the same way.
    assert_eq!(sshproxy::binary_path_of(Some("sv"), Some(cwd)), "sv");
    // Absolute: already the answer, links included.
    assert_eq!(
        sshproxy::binary_path_of(Some("/opt/homebrew/bin/sv"), Some(cwd)),
        "/opt/homebrew/bin/sv"
    );
    // Relative: `ssh` runs from a working directory of its own, so it is made
    // absolute against this one.
    assert_eq!(
        sshproxy::binary_path_of(Some("./target/debug/sv"), Some(cwd)),
        "/home/person/work/target/debug/sv"
    );
    assert_eq!(
        sshproxy::binary_path_of(Some("../sv"), Some(cwd)),
        "/home/person/sv"
    );
    // Nothing to go on.
    assert_eq!(sshproxy::binary_path_of(None, Some(cwd)), "sv");
    assert_eq!(sshproxy::binary_path_of(Some("  "), Some(cwd)), "sv");
    // And the real one is at least a usable word.
    assert!(!sshproxy::invoked_binary_path().trim().is_empty());
}

// -- the routes ------------------------------------------------------------

/// The ssh bridge hangs off the workspace's HTTP base URL, never off the ws
/// one: the relay mints `wsBaseUrl` as the `/ws` endpoint itself, and
/// `wss://<host>/ws/ssh` is a route no workspace serves.
#[test]
fn the_ssh_route_never_lands_under_the_ws_endpoint() {
    let ticket = "ws-ticket";
    assert_eq!(
        svartal::workspace::websocket_route_url("https://box.example.com", "/ssh", ticket)
            .expect("url"),
        "wss://box.example.com/ssh?wsTicket=ws-ticket"
    );
    // A workspace published under a path prefix keeps it, with the route under.
    assert_eq!(
        svartal::workspace::websocket_route_url(
            "https://edge.example.com/env/9f3c/",
            "/ssh",
            ticket
        )
        .expect("url"),
        "wss://edge.example.com/env/9f3c/ssh?wsTicket=ws-ticket"
    );
    // Plain http is a ws socket, not a wss one.
    assert_eq!(
        svartal::workspace::websocket_route_url("http://127.0.0.1:3773", "/ssh", ticket)
            .expect("url"),
        "ws://127.0.0.1:3773/ssh?wsTicket=ws-ticket"
    );
}

/// The same rule where it bites: the relay's connect response carries a
/// `wsBaseUrl` that already ends in `/ws`, and the ssh socket URL must not
/// become `/ws/ssh` because of it.
#[test]
fn the_relay_ws_endpoint_never_shapes_the_ssh_socket_url() {
    for (http_base, expected) in [
        (
            "https://workspace.example.com",
            "wss://workspace.example.com/ssh?wsTicket=ws-ticket-ssh-fixture",
        ),
        (
            "https://edge.example.com/env/9f3c",
            "wss://edge.example.com/env/9f3c/ssh?wsTicket=ws-ticket-ssh-fixture",
        ),
    ] {
        let socket_url = connect_with_endpoint(http_base, &format!("{http_base}/ws"));
        assert_eq!(socket_url, expected);
        assert!(!socket_url.contains("/ws/ssh"), "{socket_url}");
    }
}

/// The connect chain, run against one endpoint answer.
fn connect_with_endpoint(http_base: &str, ws_base: &str) -> String {
    let recorded = fixture("ssh.json");
    let jwk: PrivateJwk = serde_json::from_value(recorded["privateJwk"].clone()).expect("jwk");
    let key = DpopKey::from_private_jwk(&jwk).expect("key");
    let relay = recorded["relayUrl"].as_str().expect("relay").to_string();
    let environment_id = recorded["environmentId"]
        .as_str()
        .expect("environment")
        .to_string();
    let (endpoint_http, endpoint_ws) = (http_base.to_string(), ws_base.to_string());
    let http = common::FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{relay}/v1/environments/{environment_id}/connect") {
            return common::json_response(
                200,
                &json!({
                    "environmentId": environment_id,
                    "endpoint": {
                        "httpBaseUrl": endpoint_http,
                        "wsBaseUrl": endpoint_ws,
                        "providerKind": "cloudflare_tunnel",
                    },
                    "credential": "environment-credential",
                    "expiresAt": "2026-08-19T12:05:00.000Z",
                }),
            );
        }
        if url.ends_with("/api/auth/websocket-ticket") {
            return common::json_response(
                200,
                &json!({ "ticket": "ws-ticket-ssh-fixture", "expiresAt": "2026-08-19T12:05:00.000Z" }),
            );
        }
        common::json_response(
            200,
            &json!({
                "access_token": "an-access-token",
                "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": "terminal:operate",
            }),
        )
    });

    let target = svartal::target::ShellTarget {
        environment_id: recorded["environmentId"]
            .as_str()
            .expect("environment")
            .to_string(),
        label: "Primary".to_string(),
        machine_name: None,
        linked: true,
        machine_presence: Some("unknown".to_string()),
    };
    sshproxy::connect_bridge(
        &http,
        &sshproxy::BridgeConnectInput {
            relay_url: recorded["relayUrl"].as_str().expect("relay"),
            client_id: "svartal-cli",
            access_token: "oidc-access-token",
            target: &target,
            dpop_key: &key,
            client_metadata: svartal::workspace::CLI_CLIENT_METADATA,
        },
    )
    .expect("the connect chain")
}

/// And the RPC route keeps its own rule: `/ws` only when the base URL carries
/// no path of its own, and a base URL that carries one is left alone.
#[test]
fn the_rpc_route_leaves_a_path_carrying_base_url_alone() {
    assert_eq!(
        svartal::workspace::websocket_url("wss://box.example.com", "t").expect("url"),
        "wss://box.example.com/ws?wsTicket=t"
    );
    assert_eq!(
        svartal::workspace::websocket_url("wss://box.example.com/", "t").expect("url"),
        "wss://box.example.com/ws?wsTicket=t"
    );
    assert_eq!(
        svartal::workspace::websocket_url("wss://box.example.com/ws", "t").expect("url"),
        "wss://box.example.com/ws?wsTicket=t"
    );
    assert_eq!(
        svartal::workspace::websocket_url("wss://edge.example.com/env/9f3c/ws", "t").expect("url"),
        "wss://edge.example.com/env/9f3c/ws?wsTicket=t"
    );
}

// -- what the pump does with a broken far end ------------------------------

/// `ssh-bridge.md` §2: the bridge is binary. A text message is the far end
/// breaking the contract, and it reads as that — on stderr, with a status —
/// rather than as a connection that quietly went away.
#[test]
fn a_text_message_is_a_protocol_error() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-text");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut transport = TalkingTransport {
        inner: ScriptedTransport::new(vec![(1, ready)]),
        text_after: 1,
    };
    let mut stdio = ScriptedStdio::new(Vec::new());
    let known_hosts = directory.path().join("known_hosts");
    let error = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect_err("a text message breaks the protocol");
    assert_eq!(
        error.to_string(),
        format!(
            "The ssh bridge on {} broke the protocol: a text message",
            recorded["target"]["label"].as_str().expect("label")
        )
    );
}

/// The scripted transport, with a text message after the script runs out.
struct TalkingTransport {
    inner: ScriptedTransport,
    text_after: usize,
}

impl BinaryTransport for TalkingTransport {
    fn recv(&mut self, timeout: Duration) -> Result<Option<Vec<u8>>, TransportError> {
        match self.inner.recv(timeout)? {
            Some(message) => Ok(Some(message)),
            None if self.inner.sent.len() >= self.text_after => Err(TransportError::Protocol(
                svartal::ws::TEXT_ON_THE_SSH_BRIDGE.to_string(),
            )),
            None => Ok(None),
        }
    }

    fn send(&mut self, bytes: &[u8]) -> Result<(), TransportError> {
        self.inner.send(bytes)
    }
}

/// stdout is the SSH transport. A write that fails is bytes the far end
/// believes it delivered and `ssh` never saw, so the connection ends rather
/// than carrying on writing into a pipe nobody is reading.
#[test]
fn output_that_cannot_be_written_ends_the_connection() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-broken-stdout");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let output = encode_frame(0x82, b"a banner nobody will read");

    let mut transport = ScriptedTransport::new(vec![(1, ready), (1, output)]);
    let mut stdio = BrokenStdout::new();
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("an ended connection is an answer");
    assert_eq!(outcome.reason, sshproxy::STDOUT_GONE_REASON);
    assert_ne!(outcome.exit_code, 0);
}

/// Unless the same message carried the status: an `EXIT` that arrived with the
/// output is the connection's own answer and outranks the local failure.
#[test]
fn a_status_in_the_same_message_still_wins() {
    let recorded = fixture("ssh.json");
    let directory = TempDir::new("ssh-broken-stdout-exit");
    let ready = unhex(&strings(&recorded, "serverFrames")[0]);
    let mut message = encode_frame(0x82, b"output");
    message.extend_from_slice(&encode_frame(
        0x83,
        json!({ "reason": "sshd_exited", "exitCode": 0 })
            .to_string()
            .as_bytes(),
    ));

    let mut transport = ScriptedTransport::new(vec![(1, ready), (1, message)]);
    let mut stdio = BrokenStdout::new();
    let known_hosts = directory.path().join("known_hosts");
    let outcome = sshproxy::run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &proxy_input(&recorded, &known_hosts, "svartal-fixture"),
    )
    .expect("a complete connection");
    assert_eq!(outcome.reason, "sshd_exited");
    assert_eq!(outcome.exit_code, 0);
}
