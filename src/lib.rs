//! The Svartal terminal CLI.
//!
//! This is a port of the npm package `@svartal/cli`
//! (`ivaldi/packages/svartal-cli`), which stays as the TypeScript reference
//! implementation. The behaviour this crate must reproduce is written down in
//! `ivaldi/packages/svartal-client/SVARTAL-CONNECT.md`; the requirement
//! numbers cited throughout the source (`ID-9`, `ID-16`, …) are that
//! document's, and a comment naming one means the code above or below it is
//! contract-mandated rather than a local choice.
//!
//! Phase 1 covers identity and the read-only listings: `login`, `logout`,
//! `whoami`, `machines`, `sessions`, plus the DPoP key and the two relay calls
//! `shell` will need. The interactive shell itself is phase 2.

pub mod add;
pub mod api;
pub mod browser;
pub mod commands;
pub mod config;
pub mod dpop;
pub mod fsutil;
pub mod http;
pub mod jwt;
pub mod knit_config;
pub mod link;
pub mod loopback;
pub mod oidc;
pub mod picker;
pub mod relay;
pub mod rpc;
pub mod shell;
pub mod shortnames;
pub mod sshproxy;
pub mod store;
pub mod target;
pub mod terminal;
pub mod view;
pub mod workspace;
pub mod ws;

/// Milliseconds since the Unix epoch, from the system clock.
///
/// Every module that needs the time takes a `&dyn Fn() -> i64` instead of
/// reading the clock itself, so a test can hold a token at any point in its
/// lifetime.
pub fn now_epoch_ms() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis() as i64,
        // A clock before 1970 is not something this program can repair; the
        // token checks that follow will simply refuse everything.
        Err(_) => 0,
    }
}
