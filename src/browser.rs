//! Opening the system browser for the sign-in page.
//!
//! Best effort, and that is deliberate. A headless box, an SSH session or a
//! locked-down desktop has no browser to open, and that is not a failure: the
//! caller always prints the URL too, so the person can open it wherever they
//! are.

use std::process::{Command, Stdio};

/// Returns false when no browser could be launched.
pub trait BrowserOpener {
    fn open(&self, url: &str) -> bool;
}

pub struct SystemBrowser;

impl BrowserOpener for SystemBrowser {
    fn open(&self, url: &str) -> bool {
        let (program, leading) = if cfg!(target_os = "macos") {
            ("open", Vec::new())
        } else if cfg!(target_os = "windows") {
            // `start` is a cmd builtin, and the empty first argument is the
            // window title it would otherwise steal from the URL.
            ("cmd", vec!["/c", "start", ""])
        } else {
            ("xdg-open", Vec::new())
        };
        Command::new(program)
            .args(leading)
            .arg(url)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .is_ok()
    }
}

/// `--no-browser`, and the default in tests.
pub struct NoBrowser;

impl BrowserOpener for NoBrowser {
    fn open(&self, _url: &str) -> bool {
        false
    }
}
