//! The `ProxyCommand` the end-to-end test points a real `ssh` at.
//!
//! `sv ssh-proxy` reaches its workspace through the relay, and a test cannot
//! stand a relay up. What it can do is stand up the *other* end — a websocket
//! server on `/ssh` that spawns a real `sshd -i` — and run the real pump
//! against it. This example is that entry point: same `run_ssh_proxy`, same
//! `ProcessStdio`, same exit-status rule, with the socket URL and the client
//! key handed over in the environment instead of taken from a relay.
//!
//! It takes the argument shape `sv ssh-proxy <target>` takes, so the
//! `~/.ssh/config` block under test is the one `sv ssh-setup` writes rather
//! than a second one written for the test.
//!
//! An example, not a second `[[bin]]`: nothing about it ships.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use svartal::sshproxy::{
    CLIENT_NAME, KnownHostsTarget, PING_INTERVAL, ProcessStdio, ProxyInput, run_ssh_proxy,
};
use svartal::ws::{BinaryTransport, WebSocketTransport};

/// The bridge to open. `ws://127.0.0.1:<port>/ssh` in the test.
const URL_VARIABLE: &str = "SVARTAL_SSH_HARNESS_URL";
/// The client public key line to send in `OPEN`.
const PUBLIC_KEY_VARIABLE: &str = "SVARTAL_SSH_HARNESS_PUBLIC_KEY";
/// Where the host key from `READY` is recorded.
const KNOWN_HOSTS_VARIABLE: &str = "SVARTAL_SSH_HARNESS_KNOWN_HOSTS";

fn required(name: &str) -> String {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => {
            fail(&format!(
                "{name} is not set; this is the ssh-proxy test harness."
            ));
        }
    }
}

fn fail(message: &str) -> ! {
    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "sv: {message}");
    std::process::exit(64);
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let (verb, target) = match (arguments.first(), arguments.get(1)) {
        (Some(verb), Some(target)) if verb == "ssh-proxy" => (verb.clone(), target.clone()),
        _ => fail("usage: ssh_proxy_harness ssh-proxy <target>"),
    };
    let _ = verb;

    let mut transport = match WebSocketTransport::connect(&required(URL_VARIABLE)) {
        Ok(transport) => transport,
        Err(error) => fail(&format!("could not reach the bridge: {error}")),
    };
    let known_hosts = PathBuf::from(required(KNOWN_HOSTS_VARIABLE));
    let alias = format!("svartal-{target}");
    let public_key = required(PUBLIC_KEY_VARIABLE);
    let mut stdio = ProcessStdio::new();
    let outcome = run_ssh_proxy(
        &mut transport,
        &mut stdio,
        &ProxyInput {
            label: &target,
            public_key: &public_key,
            client_name: Some(CLIENT_NAME),
            known_hosts: KnownHostsTarget {
                path: &known_hosts,
                alias: &alias,
            },
            // The real interval; a connection this short sends none.
            ping_interval: PING_INTERVAL.max(Duration::from_secs(5)),
        },
    );
    BinaryTransport::shutdown(&mut transport);
    match outcome {
        Ok(outcome) => ExitCode::from(u8::try_from(outcome.exit_code).unwrap_or(1)),
        Err(error) => {
            let mut stderr = std::io::stderr();
            let _ = writeln!(stderr, "sv: {error}");
            ExitCode::FAILURE
        }
    }
}
