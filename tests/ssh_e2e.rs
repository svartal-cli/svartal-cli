//! `ssh` — the real one — through the real pump, into a real `sshd -i`.
//!
//! Everything between the two ends is the product: the `~/.ssh/config` block
//! `sv ssh-setup` writes, the `svartal-ssh.v1` framing, the `known_hosts` write
//! on `READY` that lets a strict host-key check pass, the half-close, and the
//! exit status. What this test stands in for is the relay: the bridge is a
//! local websocket server on `/ssh` that spawns the sshd, which is exactly what
//! the environment server does.
//!
//! **Running it.** The sshd has to be one that can start a session as a
//! non-root process. Debian's can, macOS's cannot — it aborts with "Could not
//! create new audit session", because the BSM audit session it opens needs
//! privileges — so the suite skips itself unless it finds one that works. The
//! probe is a real connection straight into the sshd, so a Linux box without a
//! usable one skips too. `SVARTAL_E2E_SSHD` names a command to use instead; it
//! is run with `sh -c`, gets `SVARTAL_E2E_KEYS` pointing at a directory holding
//! `host_key` and `authorized_keys`, and must speak SSH on its stdin and
//! stdout. A container is the obvious one:
//!
//! ```sh
//! SVARTAL_E2E_SSH_USER=root \
//! SVARTAL_E2E_SSHD='docker run -i --rm -u 0 -v "$SVARTAL_E2E_KEYS":/keys --entrypoint sh <image> -c "mkdir -p /run/sshd && exec /usr/sbin/sshd -i -e -f /dev/null -o HostKey=/keys/host_key -o AuthorizedKeysFile=/keys/authorized_keys -o PubkeyAuthentication=yes -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o UsePAM=no -o PidFile=none -o StrictModes=no"' \
//! cargo test --test ssh_e2e
//! ```

mod common;

use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, channel};

use common::TempDir;
use serde_json::Value;
use svartal::sshproxy::{
    self, ConfigBlockInput, FRAME_EXIT, FRAME_OPEN, FRAME_PING, FRAME_PONG, FRAME_READY,
    FRAME_STDIN, FRAME_STDIN_EOF, FRAME_STDOUT, FrameDecoder, encode_frame,
};

const LOCAL_SSHD: &str = "/usr/sbin/sshd";

struct Sshd {
    command: String,
    user: String,
}

/// The sshd this run can use, or `None` when there is none.
///
/// The local binary is *probed* rather than assumed: `ssh` is pointed at it as
/// its own `ProxyCommand` and asked to run `true`. That answers the only
/// question that matters — can this sshd start a session as this user — on any
/// machine, instead of guessing from the platform.
fn resolve_sshd() -> Option<Sshd> {
    let user = std::env::var("SVARTAL_E2E_SSH_USER")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(current_user);
    if let Ok(command) = std::env::var("SVARTAL_E2E_SSHD")
        && !command.trim().is_empty()
    {
        return Some(Sshd { command, user });
    }
    if !Path::new(LOCAL_SSHD).exists() {
        return None;
    }
    let local = Sshd {
        command: [
            LOCAL_SSHD,
            "-i",
            "-e",
            "-f /dev/null",
            "-o HostKey=\"$SVARTAL_E2E_KEYS/host_key\"",
            "-o AuthorizedKeysFile=\"$SVARTAL_E2E_KEYS/authorized_keys\"",
            "-o PubkeyAuthentication=yes",
            "-o PasswordAuthentication=no",
            "-o KbdInteractiveAuthentication=no",
            "-o UsePAM=no",
            "-o PidFile=none",
            // Harness only. The image's own sshd keeps the modes the contract
            // states.
            "-o StrictModes=no",
            "-o \"Subsystem sftp internal-sftp\"",
        ]
        .join(" "),
        user,
    };
    can_run_sessions(&local).then_some(local)
}

fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".into())
}

/// One real connection straight into the sshd, with no bridge in between.
fn can_run_sessions(sshd: &Sshd) -> bool {
    let keys = TempDir::new("ssh-probe");
    keygen(&keys.path().join("host_key"));
    keygen(&keys.path().join("client_key"));
    if std::fs::copy(
        keys.path().join("client_key.pub"),
        keys.path().join("authorized_keys"),
    )
    .is_err()
    {
        return false;
    }
    Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            &format!("IdentityFile={}", keys.path().join("client_key").display()),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            &format!("ProxyCommand={}", sshd.command),
            &format!("{}@svartal-probe", sshd.user),
            "true",
        ])
        .env("SVARTAL_E2E_KEYS", keys.path())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen runs on a machine that has ssh");
    assert!(status.success(), "ssh-keygen failed");
}

/// The workspace end of the bridge: `/ssh`, one `sshd -i` per connection.
///
/// A cut-down `apps/server/src/ssh/sshRoute.ts` — the frame order, the
/// authorized-keys write from `OPEN`, `READY` with the host key, `STDOUT`
/// frames, `STDIN_EOF` to a half-closed stdin, and `EXIT` with the sshd's own
/// status.
fn start_bridge(keys: PathBuf, sshd_command: String) -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let port = listener.local_addr().expect("an address").port();
    let (opened_sender, opened) = channel::<String>();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let keys = keys.clone();
            let sshd_command = sshd_command.clone();
            let opened_sender = opened_sender.clone();
            std::thread::spawn(move || {
                serve_connection(stream, &keys, &sshd_command, &opened_sender);
            });
        }
    });
    (port, opened)
}

fn serve_connection(
    stream: std::net::TcpStream,
    keys: &Path,
    sshd_command: &str,
    opened: &std::sync::mpsc::Sender<String>,
) {
    // A short read timeout, so one thread can both wait for client frames and
    // flush what the sshd produced. Blocking on the socket would deadlock the
    // banner: the client waits for output that the server never gets round to
    // sending.
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(5)));
    let mut socket = match tungstenite::accept(stream) {
        Ok(socket) => socket,
        Err(_) => return,
    };
    let mut decoder = FrameDecoder::new();
    let mut child: Option<std::process::Child> = None;
    let mut stdin: Option<std::process::ChildStdin> = None;
    let (output_sender, output) = channel::<Option<Vec<u8>>>();

    loop {
        // Anything the sshd produced goes out first, so the client sees the
        // banner before it is asked for anything.
        while let Ok(chunk) = output.try_recv() {
            match chunk {
                Some(bytes) => {
                    for frame in bytes.chunks(sshproxy::MAX_FRAME_PAYLOAD) {
                        let _ = socket.send(tungstenite::Message::Binary(
                            encode_frame(FRAME_STDOUT, frame).into(),
                        ));
                    }
                }
                None => {
                    let code = child
                        .as_mut()
                        .and_then(|child| child.wait().ok())
                        .and_then(|status| status.code())
                        .map(Value::from)
                        .unwrap_or(Value::Null);
                    let payload = serde_json::json!({ "reason": "sshd_exited", "exitCode": code });
                    let _ = socket.send(tungstenite::Message::Binary(
                        encode_frame(FRAME_EXIT, payload.to_string().as_bytes()).into(),
                    ));
                    let _ = socket.close(None);
                    let _ = socket.flush();
                    return;
                }
            }
        }

        let message = match socket.read() {
            Ok(tungstenite::Message::Binary(bytes)) => bytes.to_vec(),
            Ok(tungstenite::Message::Close(_)) => {
                if let Some(child) = child.as_mut() {
                    let _ = child.kill();
                }
                return;
            }
            Ok(_) => continue,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => {
                if let Some(child) = child.as_mut() {
                    let _ = child.kill();
                }
                return;
            }
        };

        for frame in decoder
            .push(&message)
            .expect("the client keeps the framing")
        {
            match frame.kind {
                FRAME_OPEN => {
                    let payload: Value =
                        serde_json::from_slice(&frame.payload).expect("an OPEN payload");
                    let public_key = payload["publicKey"]
                        .as_str()
                        .expect("a public key")
                        .to_string();
                    // Doc §5: the key from `OPEN` is the sshd's entire
                    // authorized-keys file.
                    std::fs::write(keys.join("authorized_keys"), format!("{public_key}\n"))
                        .expect("authorized keys");
                    let _ = opened.send(public_key);
                    let mut spawned = Command::new("sh")
                        .arg("-c")
                        .arg(sshd_command)
                        .env("SVARTAL_E2E_KEYS", keys)
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::null())
                        .spawn()
                        .expect("the sshd starts");
                    stdin = spawned.stdin.take();
                    let mut child_stdout = spawned.stdout.take().expect("stdout");
                    let sender = output_sender.clone();
                    std::thread::spawn(move || {
                        let mut buffer = [0u8; 32_768];
                        loop {
                            match child_stdout.read(&mut buffer) {
                                Ok(0) | Err(_) => {
                                    let _ = sender.send(None);
                                    return;
                                }
                                Ok(read) => {
                                    if sender.send(Some(buffer[..read].to_vec())).is_err() {
                                        return;
                                    }
                                }
                            }
                        }
                    });
                    child = Some(spawned);
                    let host_key = std::fs::read_to_string(keys.join("host_key.pub"))
                        .expect("the host key")
                        .trim()
                        .to_string();
                    let payload = serde_json::json!({
                        "connectionId": "e2e-connection",
                        "hostPublicKey": host_key,
                    });
                    let _ = socket.send(tungstenite::Message::Binary(
                        encode_frame(FRAME_READY, payload.to_string().as_bytes()).into(),
                    ));
                }
                FRAME_STDIN => {
                    if let Some(pipe) = stdin.as_mut() {
                        let _ = pipe.write_all(&frame.payload);
                        let _ = pipe.flush();
                    }
                }
                FRAME_STDIN_EOF => {
                    stdin = None;
                }
                FRAME_PING => {
                    let _ = socket.send(tungstenite::Message::Binary(
                        encode_frame(FRAME_PONG, &[]).into(),
                    ));
                }
                _ => {}
            }
        }
    }
}

/// The example that runs the real pump, built on demand.
fn harness_binary() -> Option<PathBuf> {
    let deps = std::env::current_exe().ok()?;
    let target = deps.parent()?.parent()?.to_path_buf();
    let path = target.join("examples").join("ssh_proxy_harness");
    if path.exists() {
        return Some(path);
    }
    // `cargo test --test ssh_e2e` does not build examples; ask for it once.
    let built = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["build", "--example", "ssh_proxy_harness"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .ok()?;
    (built.success() && path.exists()).then_some(path)
}

struct Fixture {
    _keys: TempDir,
    state: TempDir,
    home: TempDir,
    config_path: PathBuf,
    opened: Receiver<String>,
    user: String,
}

fn make_fixture(sshd: &Sshd) -> Fixture {
    let keys = TempDir::new("ssh-e2e-keys");
    keygen(&keys.path().join("host_key"));

    let state = TempDir::new("ssh-e2e-state");
    let ssh_directory = sshproxy::ssh_directory(state.path());
    std::fs::create_dir_all(&ssh_directory).expect("state directory");
    let client_key = sshproxy::client_key_path(state.path());
    keygen(&client_key);
    let known_hosts = sshproxy::known_hosts_path(state.path());

    let (port, opened) = start_bridge(keys.path().to_path_buf(), sshd.command.clone());

    // The `ProxyCommand` is the real pump, under the argument shape the real
    // command takes; the block around it is the one `sv ssh-setup` writes.
    let home = TempDir::new("ssh-e2e-home");
    let harness = home.path().join("sv");
    let public_key = std::fs::read_to_string(format!("{}.pub", client_key.display()))
        .expect("the client public key");
    std::fs::write(
        &harness,
        format!(
            "#!/bin/sh\nexport SVARTAL_SSH_HARNESS_URL=\"ws://127.0.0.1:{port}/ssh\"\nexport SVARTAL_SSH_HARNESS_PUBLIC_KEY=\"{}\"\nexport SVARTAL_SSH_HARNESS_KNOWN_HOSTS=\"{}\"\nexec {} \"$@\"\n",
            public_key.trim(),
            known_hosts.display(),
            harness_binary().expect("the harness example builds").display(),
        ),
    )
    .expect("harness script");
    let mut mode = std::fs::metadata(&harness).expect("stat").permissions();
    {
        use std::os::unix::fs::PermissionsExt as _;
        mode.set_mode(0o755);
    }
    std::fs::set_permissions(&harness, mode).expect("chmod");

    let config_path = home.path().join("ssh_config");
    let block = sshproxy::ssh_config_block(&ConfigBlockInput {
        alias: "svartal-e2e",
        target: "e2e",
        binary: &harness.display().to_string(),
        identity_file: &client_key.display().to_string(),
        known_hosts_file: &known_hosts.display().to_string(),
    });
    sshproxy::apply_ssh_config_block(&config_path, "svartal-e2e", &block).expect("ssh config");

    Fixture {
        _keys: keys,
        state,
        home,
        config_path,
        opened,
        user: sshd.user.clone(),
    }
}

struct SshRun {
    status: i32,
    stdout: Vec<u8>,
    stderr: String,
}

fn run_ssh(fixture: &Fixture, remote: &str, input: Option<&[u8]>) -> SshRun {
    let mut child = Command::new("ssh")
        .args([
            "-F",
            &fixture.config_path.display().to_string(),
            "-o",
            "BatchMode=yes",
            "-l",
            &fixture.user,
            "svartal-e2e",
            remote,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("ssh runs on a machine that has ssh");
    if let Some(bytes) = input {
        let mut pipe = child.stdin.take().expect("stdin");
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&bytes);
        });
    } else {
        drop(child.stdin.take());
    }
    let output = child.wait_with_output().expect("ssh finishes");
    SshRun {
        status: output.status.code().unwrap_or(-1),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    }
}

#[test]
fn ssh_runs_a_remote_command_over_the_real_pump() {
    let Some(sshd) = resolve_sshd() else {
        eprintln!("skipping: no sshd on this machine can start a session as this user");
        return;
    };
    let fixture = make_fixture(&sshd);

    let run = run_ssh(&fixture, "echo hello from the workspace", None);
    assert_eq!(run.status, 0, "{}", run.stderr);
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        "hello from the workspace"
    );
    // A `ProxyCommand`'s stderr is passed straight through to the person's
    // terminal, so a connection that worked says nothing at all.
    assert_eq!(run.stderr, "");

    // The key in `OPEN` is the one the config's `IdentityFile` names, and it is
    // what the sshd authorized this session against.
    let opened = fixture.opened.recv().expect("the bridge saw an OPEN");
    assert!(opened.starts_with("ssh-ed25519 "), "{opened}");

    // Larger than one frame's payload ceiling, and not text: `cat` only ends
    // when the client's stdin EOF has become a `STDIN_EOF` frame.
    let payload: Vec<u8> = (0..200_000u32).map(|index| (index % 251) as u8).collect();
    let echoed = run_ssh(&fixture, "cat", Some(&payload));
    assert_eq!(echoed.status, 0, "{}", echoed.stderr);
    assert_eq!(echoed.stdout.len(), payload.len());
    assert!(echoed.stdout == payload, "the bytes came back unchanged");

    // The remote command's status reaches `ssh` through the bridge.
    let failed = run_ssh(&fixture, "exit 7", None);
    assert_eq!(failed.status, 7, "{}", failed.stderr);

    // The block asks for `accept-new`, so the second connection is checked
    // against the key the first one recorded — and there is one entry, not two.
    let again = run_ssh(&fixture, "true", None);
    assert_eq!(again.status, 0, "{}", again.stderr);
    let entries = sshproxy::read_known_hosts(&sshproxy::known_hosts_path(fixture.state.path()));
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert!(
        entries[0].starts_with("svartal-e2e ssh-ed25519 "),
        "{entries:?}"
    );
    drop(fixture.home);
}
