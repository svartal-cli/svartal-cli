//! The loopback callback server.
//!
//! Port of `loopback.test.ts`. The server's only job is to hand the whole URL
//! over; every rule about what is in that URL belongs to the OIDC client.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

use svartal::loopback::{LoopbackError, LoopbackServer};

fn request(port: u16, target: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(format!("GET {target} HTTP/1.1\r\nhost: 127.0.0.1\r\nconnection: close\r\n\r\n").as_bytes())
        .unwrap();
    let mut response = String::new();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.read_to_string(&mut response).ok();
    response
}

#[test]
fn captures_the_whole_callback_url() {
    let server = LoopbackServer::bind_to("127.0.0.1", 0, "/auth/callback").unwrap();
    let port = server.port();
    let client = std::thread::spawn(move || request(port, "/auth/callback?code=the-code&state=the-state"));

    let url = server.wait_for_callback(Duration::from_secs(5)).unwrap();
    assert_eq!(url, format!("http://127.0.0.1:{port}/auth/callback?code=the-code&state=the-state"));

    let response = client.join().unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("Sign-in received."));
    // The page renames its own address so the code does not sit in history.
    assert!(response.contains("history.replaceState"));
}

#[test]
fn another_path_is_refused_without_ending_the_wait() {
    let server = LoopbackServer::bind_to("127.0.0.1", 0, "/auth/callback").unwrap();
    let port = server.port();
    let client = std::thread::spawn(move || {
        let refused = request(port, "/favicon.ico");
        let accepted = request(port, "/auth/callback?code=c&state=s");
        (refused, accepted)
    });

    let url = server.wait_for_callback(Duration::from_secs(5)).unwrap();
    assert!(url.ends_with("/auth/callback?code=c&state=s"));
    let (refused, accepted) = client.join().unwrap();
    assert!(refused.starts_with("HTTP/1.1 404 Not Found"));
    assert!(refused.contains("not the callback the terminal is waiting for"));
    assert!(accepted.starts_with("HTTP/1.1 200 OK"));
}

#[test]
fn a_held_port_is_reported_as_in_use_so_the_next_one_can_be_tried() {
    let first = LoopbackServer::bind_to("127.0.0.1", 0, "/auth/callback").unwrap();
    let error = LoopbackServer::bind_to("127.0.0.1", first.port(), "/auth/callback").unwrap_err();
    assert!(matches!(error, LoopbackError::PortInUse { .. }));
    assert!(error.to_string().contains("already in use"));
}

#[test]
fn waiting_forever_is_not_an_option() {
    let server = LoopbackServer::bind_to("127.0.0.1", 0, "/auth/callback").unwrap();
    let error = server.wait_for_callback(Duration::from_millis(150)).unwrap_err();
    assert!(matches!(error, LoopbackError::Timeout));
    assert!(error.to_string().contains("Timed out"));
}
