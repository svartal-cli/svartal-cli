//! What the shell does to keep typing feeling immediate.
//!
//! Two things sit between a keystroke and the wire, and neither is the network:
//! Nagle's algorithm on the socket, and a pump that waits on the socket and
//! only then looks at the keyboard. These tests pin both.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd as _;
use std::time::{Duration, Instant};

use svartal::shell::{accepted_term, wait_for_activity};
use svartal::terminal::{clear_one_signal, signal, signal_pipe};
use svartal::ws::WebSocketTransport;

/// A WebSocket server that completes one handshake and then holds the socket
/// open, which is all the transport needs to exist.
fn serve_one_websocket() -> (String, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let port = listener.local_addr().expect("the bound address").port();
    let handle = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            if let Ok(socket) = tungstenite::accept(stream) {
                // Hold the connection until the client is done with it.
                std::thread::sleep(Duration::from_millis(500));
                drop(socket);
            }
        }
    });
    (format!("ws://127.0.0.1:{port}/ws"), handle)
}

#[test]
fn the_shell_socket_does_not_wait_for_an_acknowledgement_before_sending_a_keystroke() {
    let (url, server) = serve_one_websocket();
    let transport = WebSocketTransport::connect(&url).expect("the local handshake");
    assert!(
        transport.is_nodelay(),
        "the shell socket must have Nagle off: it carries single keystrokes, and holding one back \
         until the previous packet is acknowledged costs a whole round trip per character"
    );
    drop(transport);
    let _ = server.join();
}

#[test]
fn a_keystroke_wakes_the_pump_without_waiting_out_the_tick() {
    let (reader, writer) = signal_pipe().expect("a pipe");
    let socket = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let idle = TcpStream::connect(socket.local_addr().expect("the bound address"))
        .expect("a connected socket with nothing to read");

    signal(writer.as_raw_fd());

    let started = Instant::now();
    let socket_ready = wait_for_activity(
        idle.as_raw_fd(),
        reader.as_raw_fd(),
        Duration::from_millis(1_000),
    );
    let waited = started.elapsed();

    assert!(!socket_ready, "the socket had nothing; only local input did");
    assert!(
        waited < Duration::from_millis(100),
        "waiting on the keyboard and the socket together must return as soon as a key is \
         pressed, not on the next tick; waited {waited:?}"
    );
}

#[test]
fn output_from_the_workspace_wakes_the_pump_too() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    let mut client = TcpStream::connect(address).expect("a connected socket");
    let (mut server, _) = listener.accept().expect("the accepted socket");
    server.write_all(b"output").expect("a write the client will see");
    server.flush().expect("a flushed write");

    let (reader, _writer) = signal_pipe().expect("a pipe");

    let started = Instant::now();
    let socket_ready = wait_for_activity(
        client.as_raw_fd(),
        reader.as_raw_fd(),
        Duration::from_millis(1_000),
    );
    let waited = started.elapsed();

    assert!(socket_ready, "the socket had data waiting");
    assert!(waited < Duration::from_millis(100), "waited {waited:?}");

    let mut received = [0u8; 6];
    client.read_exact(&mut received).expect("the bytes the server sent");
}

#[test]
fn a_quiet_shell_gives_the_wait_back_after_the_tick() {
    let (reader, _writer) = signal_pipe().expect("a pipe");
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let idle = TcpStream::connect(listener.local_addr().expect("the bound address"))
        .expect("a connected socket with nothing to read");

    let started = Instant::now();
    wait_for_activity(idle.as_raw_fd(), reader.as_raw_fd(), Duration::from_millis(50));
    let waited = started.elapsed();

    assert!(
        waited >= Duration::from_millis(40),
        "with nothing happening the wait must actually wait, not spin; waited {waited:?}"
    );
    assert!(waited < Duration::from_millis(500), "waited {waited:?}");
}

#[test]
fn each_signalled_keystroke_is_consumed_once() {
    let (reader, writer) = signal_pipe().expect("a pipe");
    let listener = TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let idle = TcpStream::connect(listener.local_addr().expect("the bound address"))
        .expect("a connected socket with nothing to read");

    // Two messages queued behind one another.
    signal(writer.as_raw_fd());
    signal(writer.as_raw_fd());

    clear_one_signal(reader.as_raw_fd());
    assert!(
        !wait_for_activity(idle.as_raw_fd(), reader.as_raw_fd(), Duration::from_millis(50)),
        "the socket still has nothing"
    );
    // The second message is still pending, so the descriptor is still readable
    // and the pump comes straight back for it instead of sleeping on it.
    let started = Instant::now();
    wait_for_activity(idle.as_raw_fd(), reader.as_raw_fd(), Duration::from_millis(1_000));
    assert!(started.elapsed() < Duration::from_millis(100), "the second message was not lost");

    clear_one_signal(reader.as_raw_fd());
    let started = Instant::now();
    wait_for_activity(idle.as_raw_fd(), reader.as_raw_fd(), Duration::from_millis(60));
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "with both messages taken there is nothing left to wake for"
    );
}

#[test]
fn the_terminal_type_sent_to_a_workspace_is_an_allowlist() {
    for accepted in [
        "xterm-256color",
        "xterm-ghostty",
        "screen.linux",
        "rxvt-unicode-256color",
        "Eterm",
        "vt100+keypad",
        "a",
        &"x".repeat(64),
    ] {
        assert_eq!(
            accepted_term(Some(accepted)).as_deref(),
            Some(accepted),
            "{accepted} is a terminfo name and must be forwarded"
        );
    }

    for refused in [
        "",
        "   ",
        "xterm 256color",
        "xterm;rm -rf /",
        "xterm\nTERM=dumb",
        "xterm=evil",
        "../../etc/terminfo",
        "xterm$(id)",
        "xterm'",
        &"x".repeat(65),
    ] {
        assert_eq!(
            accepted_term(Some(refused)),
            None,
            "{refused:?} becomes an environment variable on someone else's machine and must not \
             be forwarded"
        );
    }

    assert_eq!(accepted_term(None), None, "no TERM here means no term on the wire");
    assert_eq!(
        accepted_term(Some("  xterm-256color  ")).as_deref(),
        Some("xterm-256color"),
        "surrounding whitespace is trimmed, not refused"
    );
}
