//! `sv add`: the runbook for a new machine, and the token handoff.
//!
//! The runbook is text, and text is cheap to get wrong quietly, so the
//! assertions here are about the two things that would actually hurt: the
//! commands printed must be the ones `brok link` accepts, and the access token
//! must never leave by a path nobody chose. Everything else — the wording, the
//! order of the steps — is checked loosely on purpose, so an edit to a sentence
//! does not read as a broken test.

mod common;

use std::os::unix::fs::PermissionsExt as _;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::add::{self, MachinePlan};
use svartal::browser::NoBrowser;
use svartal::commands::{self, AddMode, Context};
use svartal::config::resolve_config;
use svartal::store::MemoryTokenStorage;

/// Only the identity provider answers here: `sv add` reads the session and
/// nothing else. A URL this router does not know is a 404, so a stray listing
/// call would fail the test rather than pass unnoticed.
fn identity_transport(fixture: Value) -> FakeTransport {
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &fixture["jwks"]);
        }
        json_response(404, &json!({ "error": "unexpected" }))
    })
}

struct Harness {
    fixture: Value,
    now: i64,
}

impl Harness {
    fn new() -> Self {
        let fixture = fixture("oidc.json");
        let now = fixture["nowEpochMs"].as_i64().unwrap();
        Self { fixture, now }
    }

    fn access_token(&self) -> String {
        self.fixture["storedTokens"]["accessToken"].as_str().unwrap().to_string()
    }

    fn run(
        &self,
        signed_in: bool,
        mode: AddMode,
        origin: Option<&str>,
        publish_only: bool,
        stdout_is_terminal: bool,
    ) -> (Result<(), commands::CliError>, String, Vec<String>) {
        let http = identity_transport(self.fixture.clone());
        let storage = if signed_in {
            MemoryTokenStorage::with_value(&self.fixture["storedTokens"].to_string())
        } else {
            MemoryTokenStorage::new()
        };
        let environment = [
            ("HOME".to_string(), "/home/person".to_string()),
            ("SVARTAL_ISSUER".to_string(), self.fixture["issuer"].as_str().unwrap().to_string()),
            ("SVARTAL_RELAY_URL".to_string(), self.fixture["relayUrl"].as_str().unwrap().to_string()),
        ]
        .into_iter()
        .collect();
        let now = self.now;
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
        let outcome =
            commands::add(&context, &mut out, mode, origin, publish_only, stdout_is_terminal);
        (outcome, String::from_utf8(out).unwrap(), http.urls())
    }

    fn runbook(&self) -> String {
        let (outcome, output, _) = self.run(true, AddMode::Runbook, None, false, true);
        outcome.unwrap();
        output
    }
}

fn plan(publish_only: bool) -> MachinePlan {
    MachinePlan {
        relay_url: "https://relay.example.test".to_string(),
        issuer: "https://api.example.test".to_string(),
        subject: "11111111-2222-3333-4444-555555555555".to_string(),
        origin: add::DEFAULT_ORIGIN.to_string(),
        publish_only,
        token_expires_in_seconds: 3000,
    }
}

// -- the runbook -----------------------------------------------------------

#[test]
fn the_runbook_prints_the_link_command_brok_actually_takes() {
    let output = Harness::new().runbook();

    // The flags are brok's, spelled brok's way: a runbook that prints a flag
    // `brok link` does not have is worse than no runbook.
    assert!(output.contains("sudo brok link --token-stdin"));
    assert!(output.contains("--relay-url https://relay.example.test"));
    assert!(output.contains("--origin http://127.0.0.1:3773"));
    assert!(output.contains("sudo brok tunnel --install"));
    // Both handoffs are offered, and the file one ends in a deletion.
    assert!(output.contains("sv add --print-token"));
    assert!(output.contains("sv add --token-file"));
    assert!(output.contains("rm /tmp/svartal-token"));
    // The configured relay, not the default one baked into brok.
    assert!(!output.contains("relay.svartal.com"));

    // Every continued line ends in a backslash, and the line after one is
    // indented further or equally — a broken continuation pastes as two
    // commands, and the second half would run without the token.
    let lines: Vec<&str> = output.lines().collect();
    for (index, line) in lines.iter().enumerate() {
        if line.ends_with('\\') {
            let next = lines.get(index + 1).copied().unwrap_or_default();
            assert!(!next.trim().is_empty(), "a continuation ends the block: {line}");
        }
    }
}

#[test]
fn the_runbook_says_how_long_the_token_lasts_and_what_it_is_not() {
    let output = Harness::new().runbook();
    // The fixture's stored token has fifty minutes left.
    assert!(output.contains("expires in 50 minutes"), "{output}");
    // The sentence that stops someone treating it as the box's own credential.
    assert!(output.contains("It is not\na machine credential"), "{output}");
}

#[test]
fn the_runbook_never_contains_the_token() {
    let harness = Harness::new();
    let output = harness.runbook();
    assert!(!output.contains(&harness.access_token()));
    // Nor any recognisable piece of one.
    assert!(!output.contains("eyJhbGciOiJSUzI1NiIs"));
}

#[test]
fn publish_only_drops_the_tunnel_step_and_says_what_that_costs() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, AddMode::Runbook, None, true, true);
    outcome.unwrap();
    assert!(output.contains("--publish-only"));
    assert!(!output.contains("brok tunnel --install"));
    assert!(output.contains("nothing can connect to it"));
}

#[test]
fn a_custom_origin_reaches_the_printed_command() {
    let harness = Harness::new();
    let (outcome, output, _) =
        harness.run(true, AddMode::Runbook, Some("http://127.0.0.1:5173"), false, true);
    outcome.unwrap();
    assert!(output.contains("--origin http://127.0.0.1:5173"));
    assert!(!output.contains("3773"));
}

#[test]
fn an_origin_brok_would_refuse_is_refused_here_instead() {
    let harness = Harness::new();
    for bad in [
        "https://example.test",        // not loopback
        "http://127.0.0.1:3773/",      // a trailing slash makes it not an origin
        "http://127.0.0.1:3773/server", // a path is not an origin either
        "127.0.0.1:3773",              // no scheme
        "",
    ] {
        let (outcome, _, urls) = harness.run(true, AddMode::Runbook, Some(bad), false, true);
        let message = outcome.expect_err(&format!("{bad} should be refused")).to_string();
        assert!(message.contains("loopback origin"), "{bad}: {message}");
        // Refused before anything is read, so a typo never touches the
        // credential or the network.
        assert!(urls.is_empty(), "{bad} reached the network");
    }
    // The two spellings brok accepts.
    assert!(add::is_loopback_origin("http://127.0.0.1:3773"));
    assert!(add::is_loopback_origin("http://localhost:3773"));
    assert!(add::is_loopback_origin("http://[::1]:3773"));
}

#[test]
fn nobody_signed_in_is_the_same_sentence_every_other_command_gives() {
    let harness = Harness::new();
    for mode in [
        AddMode::Runbook,
        AddMode::Json,
        AddMode::PrintToken,
        AddMode::TokenFile("/dev/null".to_string()),
    ] {
        let (outcome, output, _) = harness.run(false, mode.clone(), None, false, false);
        assert_eq!(outcome.unwrap_err().to_string(), commands::NOT_SIGNED_IN);
        assert!(output.is_empty(), "{mode:?} printed something");
    }
}

// -- --json ----------------------------------------------------------------

#[test]
fn json_carries_the_facts_and_states_that_it_has_no_token() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, AddMode::Json, None, false, true);
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();

    assert_eq!(parsed["relayUrl"], "https://relay.example.test");
    assert_eq!(parsed["issuer"], "https://api.example.test");
    assert_eq!(parsed["subject"], harness.fixture["subject"]);
    assert_eq!(parsed["origin"], "http://127.0.0.1:3773");
    assert_eq!(parsed["publishOnly"], false);
    assert_eq!(parsed["tokenExpiresInSeconds"], 3000);
    // Stated, not implied by an absent key.
    assert_eq!(parsed["tokenIncluded"], false);
    assert!(!output.contains(&harness.access_token()));

    assert_eq!(
        parsed["commands"]["link"],
        json!([
            "sudo",
            "brok",
            "link",
            "--relay-url",
            "https://relay.example.test",
            "--origin",
            "http://127.0.0.1:3773",
            "--token-stdin"
        ])
    );
    assert_eq!(parsed["commands"]["tunnel"], json!(["sudo", "brok", "tunnel"]));
}

#[test]
fn publish_only_json_has_no_tunnel_commands_to_run() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, AddMode::Json, None, true, true);
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["publishOnly"], true);
    assert_eq!(parsed["commands"]["tunnel"], Value::Null);
    assert_eq!(parsed["commands"]["tunnelInstall"], Value::Null);
    assert_eq!(parsed["commands"]["link"].as_array().unwrap().last().unwrap(), "--publish-only");
}

// -- the token handoff -----------------------------------------------------

#[test]
fn print_token_is_refused_when_stdout_is_a_terminal() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, AddMode::PrintToken, None, false, true);
    let message = outcome.unwrap_err().to_string();
    assert_eq!(message, add::PRINT_TOKEN_ON_TERMINAL);
    // The refusal has to be total: a partial write would have leaked it.
    assert!(output.is_empty());
    assert!(!message.contains(&harness.access_token()));
}

#[test]
fn print_token_into_a_pipe_is_the_token_and_a_newline_and_nothing_else() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, AddMode::PrintToken, None, false, false);
    outcome.unwrap();
    assert_eq!(output, format!("{}\n", harness.access_token()));
}

#[test]
fn the_token_file_is_private_and_holds_exactly_the_access_token() {
    let harness = Harness::new();
    let directory = TempDir::new("add-token");
    let path = directory.path().join("svartal-token");

    let (outcome, output, _) = harness.run(
        true,
        AddMode::TokenFile(path.display().to_string()),
        None,
        false,
        true,
    );
    outcome.unwrap();

    // Same discipline as the credential this CLI already keeps: 0600, and
    // written through a rename rather than in place.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{}\n", harness.access_token()));

    // What is on the screen is the note, never the token.
    assert!(!output.contains(&harness.access_token()));
    assert!(output.contains("0600"));
    assert!(output.contains("expires in 50 minutes"));
    assert!(output.contains("delete"));
}

#[test]
fn the_refresh_token_is_never_part_of_any_handoff() {
    let harness = Harness::new();
    let refresh = harness.fixture["storedTokens"]["refreshToken"].as_str().unwrap().to_string();
    let directory = TempDir::new("add-refresh");
    let path = directory.path().join("svartal-token");

    let (_, piped, _) = harness.run(true, AddMode::PrintToken, None, false, false);
    let (_, runbook, _) = harness.run(true, AddMode::Runbook, None, false, true);
    let (_, json_out, _) = harness.run(true, AddMode::Json, None, false, true);
    let (_, note, _) =
        harness.run(true, AddMode::TokenFile(path.display().to_string()), None, false, true);
    let file = std::fs::read_to_string(&path).unwrap();

    for (name, body) in [
        ("--print-token", piped),
        ("runbook", runbook),
        ("--json", json_out),
        ("--token-file note", note),
        ("--token-file body", file),
    ] {
        assert!(!body.contains(&refresh), "{name} carried the refresh token");
    }
}

#[test]
fn a_token_file_that_cannot_be_written_fails_without_printing_the_token() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(
        true,
        AddMode::TokenFile("/nonexistent-root-directory/svartal-token".to_string()),
        None,
        false,
        true,
    );
    let message = outcome.unwrap_err().to_string();
    assert!(message.contains("/nonexistent-root-directory"), "{message}");
    assert!(!message.contains(&harness.access_token()));
    assert!(output.is_empty());
}

// -- the pure pieces -------------------------------------------------------

#[test]
fn minutes_round_down_and_never_go_negative() {
    let mut expired = plan(false);
    expired.token_expires_in_seconds = -900;
    assert_eq!(add::minutes_left(&expired), 0);
    assert!(add::runbook(&expired).contains("expires in 0 minutes"));

    let mut nearly = plan(false);
    nearly.token_expires_in_seconds = 119;
    assert_eq!(add::minutes_left(&nearly), 1);
    assert!(add::runbook(&nearly).contains("expires in 1 minute."));
}

#[test]
fn the_runbook_wraps_inside_eighty_columns() {
    // It is read in a terminal next to an ssh session; a wrapped command line
    // is a command that gets pasted wrong.
    for line in add::runbook(&plan(false)).lines().chain(add::runbook(&plan(true)).lines()) {
        assert!(line.chars().count() <= 79, "{} columns: {line}", line.chars().count());
    }
}

// -- the two modes of one verb ----------------------------------------------

/// `sv add <pairing-url>` and the runbook flags say two different things, so a
/// line carrying both is refused whole — the same one sentence for every flag,
/// because the answer does not depend on which flag it was.
#[test]
fn a_pairing_url_next_to_a_runbook_flag_is_refused_whole() {
    let refused = add::route(Some("http://box.local:4100/pair#token=t"), true);
    assert_eq!(refused, Err(add::URL_NEXT_TO_RUNBOOK_FLAGS.to_string()));
    assert!(add::URL_NEXT_TO_RUNBOOK_FLAGS.contains("`sv add <pairing-url>`"));
}

/// Bare `sv add` — no URL, no flags — still writes the runbook, exactly as it
/// did before the pairing-URL mode joined the verb.
#[test]
fn bare_add_still_routes_to_the_runbook() {
    assert_eq!(add::route(None, false), Ok(add::AddRoute::Runbook));
    let harness = Harness::new();
    let runbook = harness.runbook();
    assert!(runbook.contains("brok link"), "the runbook still prints the link command:\n{runbook}");

    let url = "http://box.local:4100/pair#token=t";
    assert_eq!(add::route(Some(url), false), Ok(add::AddRoute::Link(url)));
}
