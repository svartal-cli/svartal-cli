//! `sv add` — the runbook for connecting a new machine, and the safe ways to
//! move the one secret it needs.
//!
//! There is no "add a machine" call to make. A machine becomes a Svartal
//! machine by **linking itself**: it holds an Ed25519 key, signs a
//! `t3-env-link+jwt` proof over a challenge, and posts it to
//! `POST /v1/client/environment-links` (`MA-6`…`MA-11`). Both of those relay
//! calls are authenticated with a **user** bearer, in the same endpoint group
//! and behind the same middleware as `GET /v1/environments` — the call
//! `sv machines` already makes. So the credential this CLI holds is exactly
//! the credential `brok link` needs, and nothing else has to exist for a new
//! box to come online today.
//!
//! The other door in the contract, `MA-14`'s one-time provisioning claim,
//! would be strictly better: the box would carry a single-use ticket instead
//! of a user token. It is not available. In the deployed relay
//! (`knithub/lib/knithub_web/relay_router.ex`) `POST /v1/provisioning/claims`
//! answers `invalid_bearer` to every caller by construction — minting is an
//! in-process Elixir call (`KnitHub.Relay.mint_claim/1`) reached only from
//! knithub's own managed-provisioning flow. Redemption is live; minting over
//! HTTP is not. Until a user-scoped mint exists, a runbook that moves a
//! short-lived user token carefully is the honest shape of this command.
//!
//! So the design rule here is about the token, not the text: **`sv add` never
//! puts an access token on a screen.** It hands it over a pipe
//! (`--print-token`, refused when stdout is a terminal) or into a `0600` file
//! (`--token-file`). What travels is the access token, which lives under an
//! hour and only authorizes the two calls `brok link` makes. The refresh
//! token, which is the durable half of the credential, never leaves this
//! machine.

use serde_json::json;
use url::Url;

/// Where a Svartal managed environment server listens on the box: the port the
/// environment image publishes to loopback
/// (`svartal-infra/scripts/managed-environment-image.sh`).
pub const DEFAULT_ORIGIN: &str = "http://127.0.0.1:3773";

/// What `sv add` needs to know to write the runbook.
#[derive(Debug, Clone)]
pub struct MachinePlan {
    /// The relay this CLI is configured against, printed into the command so
    /// a staging or self-hosted setup gets its own URL rather than the default.
    pub relay_url: String,
    pub issuer: String,
    pub subject: String,
    /// The loopback origin the environment server on the new box listens on.
    pub origin: String,
    /// No managed tunnel: the box is recorded and listed, and nothing can
    /// connect to it.
    pub publish_only: bool,
    /// Seconds of life left in the access token this runbook hands over.
    pub token_expires_in_seconds: i64,
}

/// `brok link`'s own check on `--origin`, applied here so a bad value fails in
/// the terminal that typed it rather than on the box an hour later.
///
/// Copied rather than approximated: the value must be **exactly** an origin
/// (so a trailing slash or a path is refused), and the host must be one of the
/// three spellings `brok/src/linkproof.rs` allows. `127.0.0.2` is a loopback
/// address and is still refused, because brok refuses it — a check that is
/// merely reasonable here would pass values the box then rejects.
pub fn is_loopback_origin(value: &str) -> bool {
    let trimmed = value.trim();
    let Ok(parsed) = Url::parse(trimmed) else { return false };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    if parsed.origin().ascii_serialization() != trimmed {
        return false;
    }
    let Some(host) = parsed.host_str() else { return false };
    let host = host.trim().to_ascii_lowercase();
    let host = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(&host);
    matches!(host, "127.0.0.1" | "::1" | "localhost")
}

/// Whole minutes left, rounded down, never below zero. Printed rather than a
/// timestamp: a duration needs no timezone and no date library, and the only
/// question a person has here is whether they have time to finish.
pub fn minutes_left(plan: &MachinePlan) -> i64 {
    plan.token_expires_in_seconds.max(0) / 60
}

fn link_command(plan: &MachinePlan) -> Vec<String> {
    let mut command: Vec<String> = vec![
        "sudo".into(),
        "brok".into(),
        "link".into(),
        "--relay-url".into(),
        plan.relay_url.clone(),
        "--origin".into(),
        plan.origin.clone(),
        "--token-stdin".into(),
    ];
    if plan.publish_only {
        command.push("--publish-only".into());
    }
    command
}

/// The `brok link` invocation, broken across lines at the flag boundaries so
/// it fits a terminal, with an optional stdin redirect folded onto the last
/// line. Backslash continuations only, no quoting: see `runbook`.
fn link_block(plan: &MachinePlan, indent: &str, redirect: &str) -> Vec<String> {
    let mut lines = vec![
        format!("{indent}sudo brok link --token-stdin \\"),
        format!("{indent}  --relay-url {} \\", plan.relay_url),
        format!("{indent}  --origin {}", plan.origin),
    ];
    if plan.publish_only {
        let last = lines.len() - 1;
        lines[last] = format!("{} \\", lines[last]);
        lines.push(format!("{indent}  --publish-only"));
    }
    if !redirect.is_empty() {
        let last = lines.len() - 1;
        lines[last] = format!("{}{redirect}", lines[last]);
    }
    lines
}

/// The runbook, as the person reading it sees it.
///
/// Written as steps on the *new box*, because that is where all but one of
/// them runs. The token handoff is shown twice on purpose: piped is better and
/// touches no disk, and the file form is the one that still works when sudo on
/// that box wants a password — nothing can answer a prompt on a pipe.
///
/// The remote command is passed to `ssh` as separate arguments rather than one
/// quoted string. `ssh` joins its arguments with spaces before handing them to
/// the remote shell, and none of these contain a shell metacharacter, so the
/// quotes buy nothing — and without them the ordinary backslash continuation
/// works, which is what keeps every line here inside a terminal's width.
pub fn runbook(plan: &MachinePlan) -> String {
    let minutes = minutes_left(plan);
    let mut lines: Vec<String> = [
        "Svartal has no call that adds a machine for you. A machine joins by",
        "linking itself, so these steps run on the new box, not here.",
        "",
        "1. Install brok on it. There is no public download yet, so build the",
        "   release in your brok checkout and copy it over. build-release.sh",
        "   prints the sha256 the installer asks for.",
        "",
        "     scripts/build-release.sh",
        "     scp dist/brok-release.tar.gz newbox:/tmp/",
        "     ssh newbox sudo brok-install.sh /tmp/brok-release.tar.gz <sha256>",
        "",
        "2. Link it. Piped straight in, the token touches no disk:",
        "",
        "     sv add --print-token \\",
        "       | ssh newbox \\",
    ]
    .iter()
    .map(|line| (*line).to_string())
    .collect();

    lines.extend(link_block(plan, "           ", ""));
    lines.push(String::new());
    lines.push("   That needs passwordless sudo on the box: nothing can answer a".into());
    lines.push("   password prompt on a pipe. If it asks, move the token as a file".into());
    lines.push("   instead, and delete both copies afterwards:".into());
    lines.push(String::new());
    lines.push("     sv add --token-file ./svartal-token".into());
    lines.push("     scp ./svartal-token newbox:/tmp/svartal-token".into());
    lines.push("     ssh newbox".into());
    lines.push(String::new());
    lines.push("   then, on the box:".into());
    lines.push(String::new());
    lines.extend(link_block(plan, "     ", " < /tmp/svartal-token"));
    lines.push("     rm /tmp/svartal-token".into());
    lines.push(String::new());

    if plan.publish_only {
        lines.push("   --publish-only records the box without a managed tunnel: it turns".into());
        lines.push("   up in `sv envs` and nothing can connect to it. Drop the flag, and".into());
        lines.push("   run `brok tunnel`, once it has an environment server to reach.".into());
    } else {
        lines.push("3. Start its tunnel, so Svartal can reach it:".into());
        lines.push(String::new());
        lines.push("     ssh newbox sudo brok tunnel --install".into());
        lines.push("     ssh newbox sudo brok tunnel".into());
        lines.push(String::new());
        lines.push("   --origin is where the environment server on that box listens. It".into());
        lines.push(format!("   is {} here. A box with no environment server", plan.origin));
        lines.push("   yet can link with --publish-only: it turns up in `sv envs`, and".into());
        lines.push("   nothing can connect to it.".into());
    }
    lines.push(String::new());

    lines.push(format!(
        "The token is your own sign-in and it expires in {minutes} {}. It is not",
        if minutes == 1 { "minute" } else { "minutes" }
    ));
    lines.push("a machine credential: the relay gives the box its own credential when".into());
    lines.push("the link succeeds, and that is what the box keeps. Run this again if".into());
    lines.push("the token expires before you get there.".into());
    lines.push(String::new());
    lines.push("Then run `sv envs` here. The workspace turns up once the link is".into());
    lines.push("recorded.".into());

    lines.join("\n")
}

/// `--json`: the pieces a script would otherwise scrape out of the runbook.
///
/// The token is never one of them, at any verbosity. `tokenIncluded` is there
/// so a caller reads a stated `false` rather than inferring one from a missing
/// key.
pub fn runbook_json(plan: &MachinePlan) -> String {
    let value = json!({
        "issuer": plan.issuer,
        "relayUrl": plan.relay_url,
        "subject": plan.subject,
        "origin": plan.origin,
        "publishOnly": plan.publish_only,
        "tokenExpiresInSeconds": plan.token_expires_in_seconds.max(0),
        "tokenIncluded": false,
        "commands": {
            "link": link_command(plan),
            "tunnelInstall": if plan.publish_only {
                json!(null)
            } else {
                json!(["sudo", "brok", "tunnel", "--install"])
            },
            "tunnel": if plan.publish_only {
                json!(null)
            } else {
                json!(["sudo", "brok", "tunnel"])
            },
        },
    });
    serde_json::to_string_pretty(&value).unwrap_or_default()
}

/// What `--token-file` writes: the token and a newline, nothing else.
///
/// `brok link --token-stdin` and `--token-file` both trim what they read, so a
/// trailing newline is safe, and a file a person may `cat` should end in one.
pub fn token_file_body(access_token: &str) -> Vec<u8> {
    format!("{}\n", access_token.trim()).into_bytes()
}

/// The sentence printed after `--token-file` writes. It names the file, says
/// how long it is worth anything, and says to delete it — in that order,
/// because the last one is the instruction.
pub fn token_file_note(path: &str, plan: &MachinePlan) -> String {
    let minutes = minutes_left(plan);
    format!(
        "Wrote a Svartal access token to {path} (0600). It expires in {minutes} {}, and it is your sign-in, not the machine's. Copy it to the new box, use it once, and delete both copies.",
        if minutes == 1 { "minute" } else { "minutes" }
    )
}

/// Refusing to print a token onto a terminal.
///
/// The guard is against an accident — scrollback, a shared screen, a shell
/// recording — not against a determined person, who can always add `| cat`.
/// That is the right strength: it costs a deliberate act to do the unsafe
/// thing, and nothing to do the safe one.
pub const PRINT_TOKEN_ON_TERMINAL: &str = "Refusing to print your Svartal access token to a terminal. Pipe it into the box instead (`sv add --print-token | ssh newbox '...'`), or write it to a file with `sv add --token-file <path>`.";

pub const BOTH_TOKEN_MODES: &str =
    "`sv add` takes either --print-token or --token-file, not both.";

/// One command line asking for both of `sv add`'s modes at once.
///
/// A pairing URL names the one machine to link; the runbook flags shape
/// instructions for a machine that has no URL to give yet. Half-obeying either
/// request would be a surprise, so the whole line is refused instead.
pub const URL_NEXT_TO_RUNBOOK_FLAGS: &str = "A pairing URL already says which machine to link, so the runbook options do not apply: run `sv add <pairing-url>` alone, or `sv add` without a URL for the runbook.";

/// Which of `sv add`'s two modes a command line asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddRoute<'a> {
    /// A pairing URL was given: link the machine it points at.
    Link(&'a str),
    /// No URL: write the runbook (in whichever output the flags chose).
    Runbook,
}

/// Tell `sv add`'s two modes apart, and refuse a line that asks for both.
///
/// `runbook_flag_given` is true when any of `--json`, `--origin`,
/// `--publish-only`, `--print-token` or `--token-file` was on the line; which
/// runbook output those flags then pick is the caller's decision, made only
/// after this routing says the runbook is what was asked for.
pub fn route(pairing_url: Option<&str>, runbook_flag_given: bool) -> Result<AddRoute<'_>, String> {
    match pairing_url {
        Some(_) if runbook_flag_given => Err(URL_NEXT_TO_RUNBOOK_FLAGS.to_string()),
        Some(url) => Ok(AddRoute::Link(url)),
        None => Ok(AddRoute::Runbook),
    }
}
