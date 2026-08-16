//! Short names, and the environment listing that shows them.
//!
//! A short name is the one word in this CLI the person chooses themselves, so
//! the rules around it are worth pinning: what is a usable name, what the file
//! on disk looks like, and — the part that decides which workspace a shell
//! opens on — which kind of match wins when two could.

mod common;

use std::os::unix::fs::PermissionsExt as _;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::api::{LinkRecord, Machine};
use svartal::browser::NoBrowser;
use svartal::commands::{self, Context};
use svartal::config::resolve_config;
use svartal::shortnames::{
    self, Shortnames, is_valid_shortname, read_shortnames, shortnames_path, write_shortnames,
};
use svartal::store::MemoryTokenStorage;
use svartal::target::{Resolution, resolve_shell_target};
use svartal::view::{build_env_rows, build_machines_view, format_envs_view};

// -- the file --------------------------------------------------------------

#[test]
fn a_name_is_lowercase_letters_digits_and_dashes_and_starts_with_one() {
    for name in ["web", "b", "0", "box-2", "a-b-c", &"x".repeat(32)] {
        assert!(is_valid_shortname(name), "{name} should be usable");
    }
    for name in [
        "",
        "-web",              // a dash cannot lead
        "Web",               // uppercase would never match a lowercased argument
        "my box",            // a space makes it two arguments
        "web!",
        "web/2",
        "wéb",
        &"x".repeat(33),     // one over the limit
    ] {
        assert!(!is_valid_shortname(name), "{name} should be refused");
    }
}

#[test]
fn the_file_is_a_flat_map_of_name_to_workspace_id_and_survives_a_round_trip() {
    let directory = TempDir::new("names");
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();
    names.assign("box", "env-second").unwrap();
    write_shortnames(directory.path(), &names).unwrap();

    let raw = std::fs::read_to_string(shortnames_path(directory.path())).unwrap();
    let parsed: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(parsed, json!({ "box": "env-second", "web": "env-primary" }));

    let read_back = read_shortnames(directory.path()).unwrap();
    assert_eq!(read_back, names);
    assert_eq!(read_back.environment_of("web"), Some("env-primary"));
    assert_eq!(read_back.shortname_of("env-second"), Some("box"));
}

#[test]
fn the_file_is_private_like_every_other_file_this_cli_writes() {
    let directory = TempDir::new("mode");
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();
    write_shortnames(directory.path(), &names).unwrap();

    let mode = std::fs::metadata(shortnames_path(directory.path())).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn no_file_yet_is_no_names_not_an_error() {
    let directory = TempDir::new("missing");
    assert!(read_shortnames(directory.path()).unwrap().is_empty());
}

#[test]
fn a_damaged_entry_is_dropped_and_the_rest_of_the_file_still_works() {
    let names = Shortnames::parse(
        r#"{ "web": "env-primary", "Bad Name": "env-second", "empty": "  ", "num": 4 }"#,
    );
    assert_eq!(names.len(), 1);
    assert_eq!(names.environment_of("web"), Some("env-primary"));

    // A file that is not an object at all reads as no names, the way a
    // damaged credential reads as not signed in.
    assert!(Shortnames::parse("[]").is_empty());
    assert!(Shortnames::parse("not json").is_empty());
}

#[test]
fn a_name_points_at_one_workspace_and_a_workspace_answers_to_one_name() {
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();

    // Pointing an existing name somewhere else is a rename, and says so.
    let moved = names.assign("web", "env-second").unwrap();
    assert_eq!(moved.replaced_environment.as_deref(), Some("env-primary"));
    assert_eq!(names.environment_of("web"), Some("env-second"));

    // A second name for the same workspace replaces the first, so the
    // SHORTNAME column can never be a choice between two.
    let renamed = names.assign("box", "env-second").unwrap();
    assert_eq!(renamed.replaced_shortname.as_deref(), Some("web"));
    assert_eq!(names.environment_of("web"), None);
    assert_eq!(names.shortname_of("env-second"), Some("box"));

    assert_eq!(names.remove("box").as_deref(), Some("env-second"));
    assert!(names.remove("box").is_none());
    assert!(names.is_empty());
}

#[test]
fn a_name_that_breaks_the_rule_is_refused_by_the_store_itself() {
    let mut names = Shortnames::new();
    let error = names.assign("Not A Name", "env-primary").unwrap_err();
    assert!(error.to_string().contains("is not a usable name"));
    assert!(names.assign("web", "   ").is_err());
    assert!(names.is_empty());
}

// -- resolution ------------------------------------------------------------

fn view() -> svartal::view::MachinesView {
    let machines: Vec<Machine> = vec![
        serde_json::from_value(json!({
            "id": "machine-1",
            "name": "workbench",
            "origin": "donated",
            "lifecycleState": "open",
            "presence": "online",
            "lastSeenAt": null,
            "environments": [
                { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "lifecycleState": "active" },
                // This workspace is labelled `web`, which is also a name given
                // to the other one below. That collision is the whole point.
                { "id": "row-2", "environmentId": "env-second", "label": "web", "kind": "workspace", "lifecycleState": "active" },
            ],
        }))
        .unwrap(),
    ];
    let links: Vec<LinkRecord> = vec![
        serde_json::from_value(json!({
            "environmentId": "env-primary",
            "label": "Primary",
            "endpoint": {
                "httpBaseUrl": "https://workspace.example.test",
                "wsBaseUrl": "wss://workspace.example.test",
                "providerKind": "cloudflare_tunnel",
            },
            "linkedAt": "2026-08-01T10:00:00Z",
        }))
        .unwrap(),
    ];
    build_machines_view(&machines, &links)
}

fn resolved(view: &svartal::view::MachinesView, names: &Shortnames, argument: &str) -> String {
    match resolve_shell_target(view, names, argument) {
        Resolution::Resolved(target) => target.environment_id,
        other => panic!("{argument} did not resolve: {other:?}"),
    }
}

#[test]
fn a_short_name_beats_a_label_and_a_workspace_id_beats_the_short_name() {
    let view = view();
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();

    // `web` is the label of env-second and the name of env-primary: the name
    // the person chose wins.
    assert_eq!(resolved(&view, &names, "web"), "env-primary");
    assert_eq!(resolved(&view, &names, "env-primary"), "env-primary");
    // Without the name, the label answers as it always did.
    assert_eq!(resolved(&view, &Shortnames::new(), "web"), "env-second");
    // Case and space are not a different answer here either.
    assert_eq!(resolved(&view, &names, "  WEB "), "env-primary");

    // `env-second` is a usable short name by shape, so a file could carry one
    // pointing somewhere else. The id it collides with still wins, which is
    // why `sv name` refuses to write such a name in the first place.
    let mut id_shaped = Shortnames::new();
    id_shaped.assign("env-second", "env-primary").unwrap();
    assert_eq!(resolved(&view, &id_shaped, "env-second"), "env-second");
}

#[test]
fn a_name_pointing_at_a_workspace_that_is_gone_falls_through_to_the_usual_answer() {
    let view = view();
    let mut names = Shortnames::new();
    names.assign("gone", "env-vanished").unwrap();
    assert!(matches!(
        resolve_shell_target(&view, &names, "gone"),
        Resolution::Missing(_)
    ));
    // And a name for a machine word still leaves the machine word ambiguous.
    assert!(matches!(
        resolve_shell_target(&view, &names, "workbench"),
        Resolution::Ambiguous(_)
    ));
}

// -- the listing -----------------------------------------------------------

#[test]
fn envs_lists_every_workspace_with_its_name_including_ones_on_no_visible_machine() {
    let mut names = Shortnames::new();
    names.assign("web", "env-primary").unwrap();
    let mut view = view();
    view.unregistered_links.push(
        serde_json::from_value(json!({
            "environmentId": "env-loose",
            "label": "Loose",
            "endpoint": {
                "httpBaseUrl": "https://loose.example.test",
                "wsBaseUrl": "wss://loose.example.test",
                "providerKind": "cloudflare_tunnel",
            },
            "linkedAt": "2026-08-02T10:00:00Z",
        }))
        .unwrap(),
    );

    let rows = build_env_rows(&view, &names);
    assert_eq!(
        rows.iter()
            .map(|row| (row.environment_id.as_str(), row.shortname.as_deref(), row.linked))
            .collect::<Vec<_>>(),
        vec![
            ("env-primary", Some("web"), true),
            ("env-second", None, false),
            // A link record is proof of reachability, even with no machine.
            ("env-loose", None, true),
        ]
    );
    assert_eq!(rows[2].machine_name, None);

    let table = format_envs_view(&rows);
    let lines: Vec<&str> = table.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(lines[1].starts_with("web"));
    assert!(lines[1].contains("Primary") && lines[1].contains("workbench") && lines[1].contains("online"));
    // No name yet reads as a dash, not as an empty column.
    assert!(lines[2].starts_with("-"));
    assert!(lines[2].contains("not linked"));
    assert!(lines[3].contains("env-loose"));
    assert_eq!(format_envs_view(&[]), svartal::view::NO_ENVIRONMENTS);
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

struct Harness {
    fixture: Value,
    directory: TempDir,
}

impl Harness {
    fn new(tag: &str) -> Self {
        Self { fixture: fixture("oidc.json"), directory: TempDir::new(tag) }
    }

    fn run(
        &self,
        command: impl FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), commands::CliError>,
    ) -> (Result<(), commands::CliError>, String) {
        let fixture = self.fixture.clone();
        let issuer = fixture["issuer"].as_str().unwrap().to_string();
        let relay = fixture["relayUrl"].as_str().unwrap().to_string();
        let http = FakeTransport::new(move |request| {
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
        });
        let storage = MemoryTokenStorage::with_value(&self.fixture["storedTokens"].to_string());
        let environment = [
            ("HOME".to_string(), "/home/person".to_string()),
            // Never the real `~/.config/svartal`.
            (
                "SVARTAL_CONFIG_DIR".to_string(),
                self.directory.path().to_string_lossy().to_string(),
            ),
            ("SVARTAL_ISSUER".to_string(), self.fixture["issuer"].as_str().unwrap().to_string()),
            ("SVARTAL_RELAY_URL".to_string(), self.fixture["relayUrl"].as_str().unwrap().to_string()),
        ]
        .into_iter()
        .collect();
        let now = self.fixture["nowEpochMs"].as_i64().unwrap();
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
        (outcome, String::from_utf8(out).unwrap())
    }

    fn names(&self) -> Shortnames {
        read_shortnames(self.directory.path()).unwrap()
    }
}

#[test]
fn name_records_a_workspace_found_by_any_of_the_usual_words() {
    let harness = Harness::new("name");
    let (outcome, output) =
        harness.run(|context, out| commands::name(context, out, "web", "Primary"));
    outcome.unwrap();
    assert_eq!(output.trim(), "web is Primary (env-primary).");
    assert_eq!(harness.names().environment_of("web"), Some("env-primary"));

    // Naming it again through the name it already has is a no-op, not an error.
    let (outcome, _) = harness.run(|context, out| commands::name(context, out, "web", "web"));
    outcome.unwrap();
    assert_eq!(harness.names().environment_of("web"), Some("env-primary"));
}

#[test]
fn name_refuses_a_word_that_is_not_a_name_or_that_could_never_be_used() {
    let harness = Harness::new("refuse");
    let (outcome, _) = harness.run(|context, out| commands::name(context, out, "Web Box", "Primary"));
    assert!(outcome.unwrap_err().to_string().contains("is not a usable name"));

    // A workspace id always wins resolution, so a name shaped like one would
    // sit in the file doing nothing.
    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "env-second", "Primary"));
    assert!(outcome.unwrap_err().to_string().contains("already a workspace id"));

    let (outcome, _) = harness.run(|context, out| commands::name(context, out, "web", "nowhere"));
    let message = outcome.unwrap_err().to_string();
    assert!(message.contains("No workspace called nowhere"));
    assert!(message.contains("SHORTNAME"), "the listing is offered with the refusal");

    assert!(harness.names().is_empty());
}

#[test]
fn name_lists_what_is_stored_and_remove_forgets_one() {
    let harness = Harness::new("list");
    let (outcome, output) = harness.run(commands::list_names);
    outcome.unwrap();
    assert!(output.contains("No workspace names yet"));

    harness.run(|context, out| commands::name(context, out, "web", "Primary")).0.unwrap();
    let (outcome, output) = harness.run(commands::list_names);
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(lines[1].contains("web") && lines[1].contains("env-primary"));

    let (outcome, output) = harness.run(|context, out| commands::remove_name(context, out, "web"));
    outcome.unwrap();
    assert_eq!(output.trim(), "web is no longer a name for env-primary.");
    assert!(harness.names().is_empty());

    let (outcome, _) = harness.run(|context, out| commands::remove_name(context, out, "web"));
    assert!(outcome.unwrap_err().to_string().contains("There is no workspace named web"));
}

#[test]
fn envs_prints_the_short_name_column_and_the_same_note_machines_prints() {
    let harness = Harness::new("envs");
    harness.run(|context, out| commands::name(context, out, "web", "Primary")).0.unwrap();

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, false));
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(lines[1].starts_with("web") && lines[1].contains("env-primary"));
    assert!(lines[2].starts_with("-") && lines[2].contains("env-second"));
    assert_eq!(lines.last().copied().unwrap(), svartal::view::MACHINE_STATE_NOTE);

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, true));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let rows = parsed["environments"].as_array().unwrap();
    assert_eq!(rows[0]["shortname"], json!("web"));
    assert_eq!(rows[0]["environmentId"], json!("env-primary"));
    assert_eq!(rows[1]["shortname"], Value::Null);
}

#[test]
fn a_shell_target_can_be_a_short_name() {
    let harness = Harness::new("shell-target");
    harness.run(|context, out| commands::name(context, out, "web", "Primary")).0.unwrap();
    // The step `sv shell web` takes before it touches the network: the stored
    // file, read from disk, resolving that word to a workspace.
    let names = shortnames::read_shortnames(harness.directory.path()).unwrap();
    let target = svartal::target::select_target(&view(), &names, Some("web")).unwrap();
    assert_eq!(target.environment_id, "env-primary");
    assert_eq!(target.label, "Primary");
}
