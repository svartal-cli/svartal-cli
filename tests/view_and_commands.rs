//! The listings a person actually sees.
//!
//! Port of `view.test.ts` and `commands.test.ts` in the npm CLI, including the
//! exact table text: the two CLIs are supposed to print the same thing.

mod common;

use serde_json::{Value, json};

use common::{FakeTransport, fixture, json_response};
use svartal::http::Response;
use svartal::api::{LinkRecord, Machine};
use svartal::browser::NoBrowser;
use svartal::commands::{self, Context};
use svartal::config::resolve_config;
use svartal::store::MemoryTokenStorage;
use svartal::view::{
    MACHINE_STATE_NOTE, SESSIONS_NOT_EXPOSED_NOTE, build_machines_view, filter_view_by_machine,
    format_machines_view, format_sessions_view, render_table,
};

fn machine(environments: Value) -> Machine {
    serde_json::from_value(json!({
        "id": "machine-1",
        "name": "workbench",
        "origin": "donated",
        "lifecycleState": "open",
        "presence": "unknown",
        "lastSeenAt": null,
        "environments": environments,
    }))
    .unwrap()
}

fn workspace(environment_id: &str, label: Value, kind: Value) -> Value {
    json!({
        "id": format!("row-{environment_id}"),
        "environmentId": environment_id,
        "label": label,
        "kind": kind,
        "lifecycleState": "active",
    })
}

/// A workspace with an owner on it, which is what a current server sends.
fn owned_workspace(environment_id: &str, kind: &str, owner: Value) -> Value {
    json!({
        "id": format!("row-{environment_id}"),
        "environmentId": environment_id,
        "label": environment_id,
        "kind": kind,
        "lifecycleState": "active",
        "owner": owner,
    })
}

fn link(environment_id: &str, label: &str) -> LinkRecord {
    serde_json::from_value(json!({
        "environmentId": environment_id,
        "label": label,
        "endpoint": {
            "httpBaseUrl": "https://workspace.example.test",
            "wsBaseUrl": "wss://workspace.example.test",
            "providerKind": "cloudflare_tunnel",
        },
        "linkedAt": "2026-08-01T10:00:00Z",
    }))
    .unwrap()
}

// -- the view --------------------------------------------------------------

#[test]
fn a_workspace_is_reachable_only_when_a_relay_link_exists_for_it() {
    let machines = vec![machine(json!([
        workspace("env-primary", json!("Primary"), json!("personal")),
        workspace("env-second", json!("Second"), json!("workspace")),
    ]))];
    let view = build_machines_view(&machines, &[link("env-primary", "Primary")], Some("person"));

    assert_eq!(
        view.rows.iter().map(|row| (row.environment_id.as_str(), row.linked)).collect::<Vec<_>>(),
        vec![("env-primary", true), ("env-second", false)]
    );
    assert_eq!(view.rows[0].linked_at.as_deref(), Some("2026-08-01T10:00:00Z"));
    assert!(view.unregistered_links.is_empty());
}

#[test]
fn a_link_whose_workspace_is_on_no_visible_machine_is_still_reported() {
    let machines = vec![machine(json!([workspace("env-primary", json!("Primary"), json!("personal"))]))];
    let view = build_machines_view(
        &machines,
        &[link("env-primary", "Primary"), link("env-elsewhere", "Lab")],
        Some("person"),
    );
    assert_eq!(
        view.unregistered_links.iter().map(|entry| entry.environment_id.as_str()).collect::<Vec<_>>(),
        vec!["env-elsewhere"]
    );
    assert!(format_machines_view(&view, false).contains("env-elsewhere"));
}

#[test]
fn a_workspace_with_no_label_falls_back_to_its_id() {
    let machines = vec![machine(json!([workspace("env-primary", json!("   "), Value::Null)]))];
    let view = build_machines_view(&machines, &[], Some("person"));
    assert_eq!(view.rows[0].label, "env-primary");
    assert_eq!(view.rows[0].kind, "-");
}

#[test]
fn nothing_yet_is_said_plainly() {
    assert!(format_machines_view(&build_machines_view(&[], &[], Some("person")), false)
        .contains("No machines yet"));
}

#[test]
fn the_table_pads_every_column_and_leaves_no_trailing_spaces() {
    let output = render_table(
        &["NAME", "STATE"],
        &[
            vec!["a".to_string(), "online".to_string()],
            vec!["longer-name".to_string(), "offline".to_string()],
        ],
    );
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        vec!["NAME         STATE", "a            online", "longer-name  offline"]
    );
}

#[test]
fn the_notes_never_claim_a_live_check() {
    assert!(MACHINE_STATE_NOTE.contains("not a live check"));
    let machines = vec![machine(json!([workspace("env-primary", json!("Primary"), json!("personal"))]))];
    let reachable =
        format_sessions_view(&build_machines_view(&machines, &[link("env-primary", "Primary")], Some("person")));
    assert!(reachable.contains("env-primary"));
    assert!(reachable.contains(SESSIONS_NOT_EXPOSED_NOTE));
    let unreachable = format_sessions_view(&build_machines_view(&machines, &[], Some("person")));
    assert!(unreachable.contains("No workspace you can reach."));
    assert!(unreachable.contains(SESSIONS_NOT_EXPOSED_NOTE));
}

#[test]
fn filtering_accepts_a_machine_name_a_machine_id_or_a_workspace_id() {
    let machines = vec![machine(json!([workspace("env-primary", json!("Primary"), json!("personal"))]))];
    let view = build_machines_view(&machines, &[link("env-primary", "Primary")], Some("person"));
    for needle in ["workbench", "WORKBENCH", "machine-1", "env-primary"] {
        assert_eq!(filter_view_by_machine(&view, needle).rows.len(), 1, "{needle}");
    }
    assert!(filter_view_by_machine(&view, "other").rows.is_empty());
}

// -- whose workspace it is -------------------------------------------------

/// The laptop this rule was written for: your personal workspace, a second
/// person's personal workspace on the same machine, and a shared one that
/// belongs to nobody in particular.
fn two_people_on_one_machine(viewer: Option<&str>) -> svartal::view::MachinesView {
    let machines = vec![machine(json!([
        owned_workspace("env-mine", "personal", json!("person")),
        owned_workspace("env-theirs", "personal", json!("other")),
        owned_workspace("env-shared", "workspace", Value::Null),
    ]))];
    build_machines_view(&machines, &[], viewer)
}

#[test]
fn a_second_persons_personal_workspace_is_not_in_your_listing() {
    let view = two_people_on_one_machine(Some("person"));
    assert_eq!(
        view.yours().rows.iter().map(|row| row.environment_id.as_str()).collect::<Vec<_>>(),
        vec!["env-mine", "env-shared"]
    );
    // The view itself keeps every row; only the listing leaves one out.
    assert_eq!(view.rows.len(), 3);
    assert_eq!(view.rows[1].owner.as_deref(), Some("other"));
    assert!(view.rows[1].belongs_to_another);
    assert!(!view.rows[0].belongs_to_another, "your own personal workspace is yours");
    assert!(!view.rows[2].belongs_to_another, "a shared workspace belongs to nobody");

    let table = format_machines_view(&view.yours(), false);
    assert!(!table.contains("env-theirs"));
    assert!(!table.contains("OWNER"), "there is no owner column without --all");
}

#[test]
fn all_shows_the_other_rows_and_only_then_names_their_owner() {
    let table = format_machines_view(&two_people_on_one_machine(Some("person")), true);
    let lines: Vec<&str> = table.lines().collect();
    assert!(lines[0].contains("OWNER"));
    assert!(lines[2].contains("env-theirs") && lines[2].contains("other"));
    // An owner Svartal did not name reads as a dash, like every other unknown
    // cell in these tables.
    assert_eq!(
        lines[3].split_whitespace().collect::<Vec<_>>(),
        vec!["workbench", "env-shared", "env-shared", "workspace", "-", "active", "not", "linked", "unknown"]
    );
}

#[test]
fn without_a_username_on_either_side_nothing_is_somebody_elses() {
    // An older server sends no owner at all, and a session that never carried
    // a username cannot compare one. Both keep every row listed.
    let no_owner = build_machines_view(
        &[machine(json!([workspace("env-primary", json!("Primary"), json!("personal"))]))],
        &[],
        Some("person"),
    );
    assert_eq!(no_owner.yours().rows.len(), 1);
    assert_eq!(two_people_on_one_machine(None).yours().rows.len(), 3);
}

// -- the commands ----------------------------------------------------------

const MACHINES_BODY: &str = r#"{
  "data": [
    {
      "id": "machine-1",
      "name": "workbench",
      "origin": "donated",
      "lifecycleState": "open",
      "presence": "online",
      "lastSeenAt": "2026-08-13T09:00:00Z",
      "environments": [
        { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "lifecycleState": "active" },
        { "id": "row-2", "environmentId": "env-second", "label": "Second", "kind": "workspace", "lifecycleState": "active" }
      ]
    }
  ]
}"#;

const ENVIRONMENTS_BODY: &str = r#"{
  "environments": [
    {
      "environmentId": "env-primary",
      "label": "Primary",
      "endpoint": { "httpBaseUrl": "https://workspace.example.test", "wsBaseUrl": "wss://workspace.example.test", "providerKind": "cloudflare_tunnel" },
      "linkedAt": "2026-08-01T10:00:00Z"
    }
  ]
}"#;

/// The identity provider and the data plane behind one transport.
fn signed_in_transport(fixture: Value) -> FakeTransport {
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let relay = fixture["relayUrl"].as_str().unwrap().to_string();
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &fixture["jwks"]);
        }
        if url == format!("{issuer}/api/v1/client/machines") {
            return json_response(200, &serde_json::from_str(MACHINES_BODY).unwrap());
        }
        if url == format!("{relay}/v1/environments") {
            return json_response(200, &serde_json::from_str(ENVIRONMENTS_BODY).unwrap());
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

    fn run(
        &self,
        signed_in: bool,
        command: impl FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), svartal::commands::CliError>,
    ) -> (Result<(), svartal::commands::CliError>, String, Vec<String>) {
        let http = signed_in_transport(self.fixture.clone());
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
        let outcome = command(&context, &mut out);
        (outcome, String::from_utf8(out).unwrap(), http.urls())
    }

    /// `run`, with the data plane answered by `respond` instead of the
    /// fixtures. The identity provider still answers normally.
    fn run_with_data_plane(
        &self,
        respond: impl Fn(&str) -> Option<Response> + Send + Sync + 'static,
        command: impl FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), svartal::commands::CliError>,
    ) -> (Result<(), svartal::commands::CliError>, String, Vec<String>) {
        let fixture = self.fixture.clone();
        let issuer = fixture["issuer"].as_str().unwrap().to_string();
        let http = FakeTransport::new(move |request| {
            let url = request.url.as_str();
            if let Some(response) = respond(url) {
                return response;
            }
            if url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &fixture["discovery"]);
            }
            if url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &fixture["jwks"]);
            }
            json_response(404, &json!({ "error": "unexpected" }))
        });
        let storage = MemoryTokenStorage::with_value(&self.fixture["storedTokens"].to_string());
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
        let outcome = command(&context, &mut out);
        (outcome, String::from_utf8(out).unwrap(), http.urls())
    }
}

/// The two listings are independent requests, fetched concurrently. When both
/// fail, the reported error is still the API's — the sentence the sequential
/// fetch produced — so failing faster never changes what the person reads.
#[test]
fn when_both_listings_fail_the_api_error_is_the_one_reported() {
    let harness = Harness::new();
    let (outcome, output, urls) = harness.run_with_data_plane(
        |url| {
            (url.contains("/api/v1/client/machines") || url.contains("/v1/environments"))
                .then(|| json_response(500, &json!({ "error": "boom" })))
        },
        |context, out| commands::machines(context, out, false, false),
    );
    let error = outcome.unwrap_err();
    assert_eq!(error.0, "Could not list your machines.");
    assert_eq!(output, "");
    // Both requests were sent: neither listing waits on the other's answer.
    assert!(urls.iter().any(|url| url.contains("/api/v1/client/machines")));
    assert!(urls.iter().any(|url| url.contains("/v1/environments")));
}

#[test]
fn whoami_prints_the_verified_subject_from_the_stored_session() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, |context, out| commands::whoami(context, out, false));
    outcome.unwrap();
    assert_eq!(
        output.lines().collect::<Vec<_>>(),
        vec![
            format!("Subject: {}", harness.fixture["subject"].as_str().unwrap()).as_str(),
            "Username: person",
            "Name: A Person",
            "Email: person@example.test",
        ]
    );
}

#[test]
fn whoami_json_is_the_same_four_fields() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, |context, out| commands::whoami(context, out, true));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        parsed,
        json!({
            "subject": harness.fixture["subject"],
            "username": "person",
            "name": "A Person",
            "email": "person@example.test",
        })
    );
}

#[test]
fn machines_joins_the_machine_listing_with_the_relay_links() {
    let harness = Harness::new();
    let (outcome, output, urls) =
        harness.run(true, |context, out| commands::machines(context, out, false, false));
    outcome.unwrap();
    let issuer = harness.fixture["issuer"].as_str().unwrap();
    let relay = harness.fixture["relayUrl"].as_str().unwrap();
    assert!(urls.contains(&format!("{issuer}/api/v1/client/machines")));
    assert!(urls.contains(&format!("{relay}/v1/environments")));

    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("MACHINE"));
    assert!(lines[1].contains("workbench") && lines[1].contains("env-primary") && lines[1].contains("linked"));
    assert!(lines[2].contains("env-second") && lines[2].contains("not linked"));
    assert_eq!(lines.last().copied().unwrap(), MACHINE_STATE_NOTE);
}

#[test]
fn machines_json_emits_the_same_join_as_data() {
    let harness = Harness::new();
    let (outcome, output, _) =
        harness.run(true, |context, out| commands::machines(context, out, true, false));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let workspaces = parsed["workspaces"].as_array().unwrap();
    assert_eq!(
        workspaces
            .iter()
            .map(|row| (row["environmentId"].as_str().unwrap(), row["linked"].as_bool().unwrap()))
            .collect::<Vec<_>>(),
        vec![("env-primary", true), ("env-second", false)]
    );
    assert_eq!(workspaces[0]["linkedAt"].as_str().unwrap(), "2026-08-01T10:00:00Z");
    assert!(parsed["unregisteredLinks"].as_array().unwrap().is_empty());
}

/// The same machine `two_people_on_one_machine` describes, on the wire. The
/// shared workspace carries no `owner` key at all, which is what an older
/// server sends for every row.
const SHARED_MACHINE_BODY: &str = r#"{
  "data": [
    {
      "id": "machine-1",
      "name": "m3",
      "origin": "donated",
      "lifecycleState": "open",
      "presence": "online",
      "lastSeenAt": "2026-08-13T09:00:00Z",
      "environments": [
        { "id": "row-1", "environmentId": "env-mine", "label": "Mine", "kind": "personal", "owner": "person", "lifecycleState": "active" },
        { "id": "row-2", "environmentId": "env-theirs", "label": "Theirs", "kind": "personal", "owner": "other", "lifecycleState": "active" },
        { "id": "row-3", "environmentId": "env-shared", "label": "Shared", "kind": "workspace", "lifecycleState": "active" }
      ]
    }
  ]
}"#;

const MINE_IS_LINKED_BODY: &str = r#"{
  "environments": [
    {
      "environmentId": "env-mine",
      "label": "Mine",
      "endpoint": { "httpBaseUrl": "https://workspace.example.test", "wsBaseUrl": "wss://workspace.example.test", "providerKind": "cloudflare_tunnel" },
      "linkedAt": "2026-08-01T10:00:00Z"
    }
  ]
}"#;

fn shared_machine(url: &str) -> Option<Response> {
    if url.contains("/api/v1/client/machines") {
        return Some(json_response(200, &serde_json::from_str(SHARED_MACHINE_BODY).unwrap()));
    }
    if url.ends_with("/v1/environments") {
        return Some(json_response(200, &serde_json::from_str(MINE_IS_LINKED_BODY).unwrap()));
    }
    None
}

#[test]
fn machines_lists_your_own_workspaces_and_all_adds_the_other_ones() {
    let harness = Harness::new();
    let (outcome, output, _) = harness
        .run_with_data_plane(shared_machine, |context, out| {
            commands::machines(context, out, false, false)
        });
    outcome.unwrap();
    assert!(output.contains("env-mine") && output.contains("env-shared"));
    assert!(!output.contains("env-theirs"), "somebody else's personal workspace is not yours");
    assert!(!output.contains("OWNER"));
    assert_eq!(output.lines().last().unwrap(), MACHINE_STATE_NOTE);

    let (outcome, output, _) = harness
        .run_with_data_plane(shared_machine, |context, out| {
            commands::machines(context, out, false, true)
        });
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].contains("OWNER"));
    assert!(lines[1].contains("env-mine") && lines[1].contains("person"));
    assert!(lines[2].contains("env-theirs") && lines[2].contains("other"));
    assert!(lines[3].contains("env-shared"));
}

#[test]
fn machines_json_carries_every_workspace_and_its_owner_whatever_all_says() {
    let harness = Harness::new();
    for all in [false, true] {
        let (outcome, output, _) = harness
            .run_with_data_plane(shared_machine, move |context, out| {
                commands::machines(context, out, true, all)
            });
        outcome.unwrap();
        let parsed: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(
            parsed["workspaces"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| (row["environmentId"].clone(), row["owner"].clone()))
                .collect::<Vec<_>>(),
            vec![
                (json!("env-mine"), json!("person")),
                (json!("env-theirs"), json!("other")),
                // No `owner` key on the wire reads as no owner, not a refusal
                // to decode the listing.
                (json!("env-shared"), Value::Null),
            ]
        );
    }
}

#[test]
fn sessions_lists_reachable_workspaces_and_says_sessions_are_not_exposed_yet() {
    let harness = Harness::new();
    let (outcome, output, _) =
        harness.run(true, |context, out| commands::sessions(context, out, false, Some("workbench")));
    outcome.unwrap();
    assert!(output.contains("env-primary"));
    assert!(!output.contains("env-second"));
    assert!(output.contains("not readable with a terminal sign-in yet"));
}

#[test]
fn sessions_json_says_it_cannot_see_sessions_rather_than_reporting_none() {
    let harness = Harness::new();
    let (outcome, output, _) =
        harness.run(true, |context, out| commands::sessions(context, out, true, None));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(parsed["sessions"], Value::Null);
    assert_eq!(parsed["sessionsAvailable"], json!(false));
    assert_eq!(parsed["workspaces"].as_array().unwrap().len(), 1);
}

#[test]
fn a_command_that_reads_data_never_opens_a_browser_when_nobody_is_signed_in() {
    let harness = Harness::new();
    let (outcome, output, urls) =
        harness.run(false, |context, out| commands::whoami(context, out, false));
    let error = outcome.unwrap_err();
    assert!(error.to_string().contains("sv login"));
    assert!(output.is_empty());
    assert!(urls.is_empty());
}

#[test]
fn logout_says_when_there_was_nothing_to_sign_out_of() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(false, commands::logout);
    outcome.unwrap();
    assert_eq!(output.trim(), "There was nothing to sign out of.");
}

#[test]
fn login_stops_at_already_signed_in() {
    let harness = Harness::new();
    let (outcome, output, _) = harness.run(true, commands::login);
    outcome.unwrap();
    assert_eq!(output.trim(), "Already signed in as person.");
}
