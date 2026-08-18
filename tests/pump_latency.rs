//! What the pump itself adds between a keystroke and the wire.
//!
//! The network is not measurable from a test, and it is not the part this
//! client controls. What this client controls is how long a typed byte sits in
//! the loop before it is sent. That is measured here over a real WebSocket on
//! loopback, against a server that echoes every write straight back, so the
//! only thing left in the number is the loop.
//!
//! The comparison is the point: the same pump, the same server, the same
//! keystrokes, with and without the descriptor that lets the loop wait on the
//! socket and the keyboard at once.

use std::net::TcpListener;
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant};

use svartal::rpc::RpcClient;
use svartal::shell::{
    InputPoll, LocalTerminal, PumpInput, ShellSession, TerminalKind, run_shell_pump,
};
use svartal::terminal::{TerminalSize, clear_one_signal, signal, signal_pipe};
use svartal::ws::WebSocketTransport;

const SAMPLES: usize = 25;
/// Long enough that each keystroke lands at an unrelated point in the loop,
/// which is what a person typing does.
const GAP: Duration = Duration::from_millis(37);

/// A workspace that answers `terminal.write` with the byte it was given.
fn spawn_echo_workspace() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    let handle = std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else { return };
        let Ok(mut socket) = tungstenite::accept(stream) else { return };
        let mut attach_id = String::new();
        loop {
            let Ok(message) = socket.read() else { return };
            let tungstenite::Message::Text(text) = message else { continue };
            let Ok(frame) = serde_json::from_str::<serde_json::Value>(text.as_str()) else {
                continue;
            };
            match frame.get("_tag").and_then(serde_json::Value::as_str) {
                Some("Ping") => {
                    let _ = socket.send(tungstenite::Message::Text(r#"{"_tag":"Pong"}"#.into()));
                }
                Some("Request") => {
                    let tag = frame.get("tag").and_then(serde_json::Value::as_str).unwrap_or("");
                    let id =
                        frame.get("id").and_then(serde_json::Value::as_str).unwrap_or("").to_string();
                    if tag == "terminal.attach" {
                        attach_id = id;
                        continue;
                    }
                    if tag == "terminal.write" {
                        let echo = serde_json::json!({
                            "_tag": "Chunk",
                            "requestId": attach_id,
                            "values": [{ "type": "output", "data": "x" }],
                        });
                        let _ = socket
                            .send(tungstenite::Message::Text(echo.to_string().into()));
                    }
                }
                _ => {}
            }
        }
    });
    (format!("ws://127.0.0.1:{port}/ws"), handle)
}

/// A terminal whose keystrokes arrive from somewhere else, at a time the pump
/// does not choose — the only shape in which the loop's own delay is visible.
struct TypistTerminal {
    keystrokes: Receiver<Instant>,
    ready: Option<OwnedFd>,
    /// Set when the pump can see the readiness descriptor. `false` reproduces
    /// the loop as it was: socket first, keyboard afterwards.
    expose_ready: bool,
    pending: Option<Instant>,
    round_trips: Vec<Duration>,
    remaining: usize,
}

impl LocalTerminal for TypistTerminal {
    fn size(&self) -> TerminalSize {
        TerminalSize { cols: 80, rows: 24 }
    }

    fn write(&mut self, _data: &str) {
        if let Some(sent_at) = self.pending.take() {
            self.round_trips.push(sent_at.elapsed());
        }
    }

    fn take_input(&mut self) -> InputPoll {
        if let Some(fd) = self.ready.as_ref().map(AsRawFd::as_raw_fd) {
            clear_one_signal(fd);
        }
        match self.keystrokes.try_recv() {
            Ok(typed_at) => {
                if self.remaining == 0 {
                    return InputPoll::Ended;
                }
                self.remaining -= 1;
                self.pending = Some(typed_at);
                InputPoll::Data("x".to_string())
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => InputPoll::None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => InputPoll::Ended,
        }
    }

    fn take_resize(&mut self) -> bool {
        false
    }

    fn ready_fd(&self) -> Option<std::os::fd::RawFd> {
        if self.expose_ready { self.ready.as_ref().map(AsRawFd::as_raw_fd) } else { None }
    }
}

fn median(values: &mut [Duration]) -> Duration {
    values.sort_unstable();
    values[values.len() / 2]
}

fn p95(values: &mut [Duration]) -> Duration {
    values.sort_unstable();
    values[(values.len() * 95).div_ceil(100).saturating_sub(1)]
}

/// Type `SAMPLES` keystrokes at a workspace that echoes them, and report how
/// long each one took to come back.
fn measure(expose_ready: bool) -> Vec<Duration> {
    let (url, server) = spawn_echo_workspace();
    let transport = WebSocketTransport::connect(&url).expect("the local handshake");
    let mut rpc = RpcClient::new(transport);

    let (reader, writer) = signal_pipe().expect("a pipe");
    let (sender, keystrokes): (Sender<Instant>, Receiver<Instant>) = channel();
    let notify = writer.as_raw_fd();
    let typist = std::thread::spawn(move || {
        // Keep the write end alive for the whole run.
        let writer = writer;
        for _ in 0..=SAMPLES {
            std::thread::sleep(GAP);
            if sender.send(Instant::now()).is_err() {
                break;
            }
            signal(notify);
        }
        drop(writer);
    });

    let mut terminal = TypistTerminal {
        keystrokes,
        ready: Some(reader),
        expose_ready,
        pending: None,
        round_trips: Vec::new(),
        remaining: SAMPLES,
    };

    let session = ShellSession {
        kind: TerminalKind::Shell,
        thread_id: "svartal-shell:subject".to_string(),
        terminal_id: "shell-probe".to_string(),
        cwd: "/workspace".to_string(),
        term: None,
        colorterm: None,
        reattached: false,
    };
    let _ = run_shell_pump(
        &mut rpc,
        &mut terminal,
        &PumpInput { session: &session, label: "Probe", subject: "subject" },
    );

    // The workspace thread reads until the socket goes away, so the socket has
    // to go away before it is joined.
    drop(rpc);
    let _ = typist.join();
    let _ = server.join();
    terminal.round_trips
}

#[test]
fn the_pump_no_longer_makes_a_keystroke_wait_for_its_own_turn() {
    let mut without = measure(false);
    let mut with = measure(true);

    assert_eq!(without.len(), SAMPLES, "every keystroke came back");
    assert_eq!(with.len(), SAMPLES, "every keystroke came back");

    let (before_median, before_p95) = (median(&mut without), p95(&mut without));
    let (after_median, after_p95) = (median(&mut with), p95(&mut with));
    println!(
        "loopback keystroke round trip -- socket-first: median {before_median:?} p95 \
         {before_p95:?}; socket-and-keyboard: median {after_median:?} p95 {after_p95:?}"
    );

    // The old loop blocked on the socket for a full tick before looking at the
    // keyboard, so a keystroke waited half a tick on average and a whole tick
    // at worst. On loopback that wait is the entire number.
    assert!(
        before_median >= Duration::from_millis(10),
        "the socket-first loop is expected to cost most of a tick; measured {before_median:?}"
    );
    assert!(
        after_median < Duration::from_millis(5),
        "waiting on both descriptors must send a keystroke as soon as it is typed; measured \
         {after_median:?}"
    );
    assert!(
        after_p95 < before_median,
        "even the slow keystrokes must beat the old typical one: {after_p95:?} vs {before_median:?}"
    );
}
