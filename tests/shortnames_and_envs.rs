//! Short names, and the environment listing that shows them.
//!
//! A short name is the one word in this CLI the person chooses themselves, so
//! the rules around it are worth pinning: what is a usable name, what the file
//! on disk looks like, and — the part that decides which workspace a shell
//! opens on — which kind of match wins when two could.

mod common;

use std::os::unix::fs::PermissionsExt as _;
use std::sync::{Arc, Mutex};

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
use svartal::view::{
    build_env_rows, build_machines_view, format_envs_json, format_envs_view, own_env_rows,
    reachable_cell,
};

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
    build_machines_view(&machines, &links, Some("person"))
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

    let table = format_envs_view(&rows, false);
    let lines: Vec<&str> = table.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(lines[1].starts_with("web"));
    assert!(lines[1].contains("Primary") && lines[1].contains("workbench") && lines[1].contains("online"));
    // No name yet reads as a dash, not as an empty column.
    assert!(lines[2].starts_with("-"));
    assert!(lines[2].contains("not linked"));
    assert!(lines[3].contains("env-loose"));
    assert_eq!(format_envs_view(&[], false), svartal::view::NO_ENVIRONMENTS);
}

// -- what `not linked` was hiding ------------------------------------------

/// One machine with three personal workspaces on it, none of them linked: one
/// Svartal is relinking, one nobody owns, and one from a server that says
/// nothing about intent at all.
fn intent_view() -> svartal::view::MachinesView {
    let machines: Vec<Machine> = vec![
        serde_json::from_value(json!({
            "id": "machine-1",
            "name": "m3",
            "origin": "donated",
            "lifecycleState": "open",
            "presence": "online",
            "lastSeenAt": null,
            "environments": [
                { "id": "row-1", "environmentId": "env-relinking", "label": "Coming back", "kind": "personal", "owner": "person", "lifecycleState": "active", "intentState": "relinking" },
                { "id": "row-2", "environmentId": "env-unclaimed", "label": "Nobody's", "kind": "personal", "lifecycleState": "active", "intentState": "unclaimed" },
                // An older server sends no `intentState` key at all.
                { "id": "row-3", "environmentId": "env-quiet", "label": "Quiet", "kind": "personal", "owner": "person", "lifecycleState": "active" },
            ],
        }))
        .unwrap(),
    ];
    build_machines_view(&machines, &[], Some("person"))
}

#[test]
fn the_reachable_cell_says_which_kind_of_not_linked_this_is() {
    assert_eq!(reachable_cell(true, None), "linked");
    // A link being restored is still a link, so it does not read as gone.
    assert_eq!(reachable_cell(false, Some("relinking")), "relinking");
    assert_eq!(reachable_cell(false, Some("unclaimed")), "unclaimed");
    assert_eq!(reachable_cell(false, None), "not linked");
    // Every other intent is an ordinary workspace you hold no link to.
    assert_eq!(reachable_cell(false, Some("ready")), "not linked");
    // And holding the link wins over whatever Svartal intends next.
    assert_eq!(reachable_cell(true, Some("relinking")), "linked");
}

#[test]
fn a_workspace_nobody_owns_is_not_in_your_list_but_is_in_all_of_them() {
    let rows = build_env_rows(&intent_view(), &Shortnames::new());
    let yours = own_env_rows(&rows);
    assert_eq!(
        yours.iter().map(|row| row.environment_id.as_str()).collect::<Vec<_>>(),
        // The unclaimed one is gone; the relinking one and the one from the
        // older server are both still yours.
        vec!["env-relinking", "env-quiet"]
    );

    // `--all` is where something that exists stays findable.
    let all = format_envs_view(&rows, true);
    assert!(all.lines().any(|line| line.contains("env-unclaimed") && line.contains("unclaimed")));

    let table = format_envs_view(&yours, false);
    assert!(!table.contains("env-unclaimed"));
    assert!(table.lines().any(|line| line.contains("env-relinking") && line.contains("relinking")));
    // A server that says nothing about intent prints what it always printed.
    assert!(table.lines().any(|line| line.contains("env-quiet") && line.contains("not linked")));
}

#[test]
fn the_json_listing_carries_the_intent_it_was_given() {
    let rows = build_env_rows(&intent_view(), &Shortnames::new());
    let parsed: Value = serde_json::from_str(&format_envs_json(&rows)).unwrap();
    assert_eq!(
        parsed["environments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row["environmentId"].as_str().unwrap(), row["intentState"].clone()))
            .collect::<Vec<_>>(),
        vec![
            ("env-relinking", json!("relinking")),
            ("env-unclaimed", json!("unclaimed")),
            // Explicitly null rather than missing: the key is always there.
            ("env-quiet", Value::Null),
        ]
    );
}

#[test]
fn the_note_under_the_table_explains_both_new_words() {
    let note = svartal::view::MACHINE_STATE_NOTE;
    assert_eq!(note.lines().count(), 1);
    assert!(note.contains("relinking means Svartal is restoring your link"));
    assert!(note.contains("`sv host up`"));
    assert!(note.contains("unclaimed means nobody owns that workspace"));
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
        { "id": "row-1", "environmentId": "env-primary", "label": "Primary", "kind": "personal", "owner": "person", "lifecycleState": "active" },
        { "id": "row-2", "environmentId": "env-second", "label": "Second", "kind": "workspace", "lifecycleState": "active" },
        { "id": "row-3", "environmentId": "env-theirs", "label": "Theirs", "kind": "personal", "owner": "other", "lifecycleState": "active" }
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

/// The commands under test now write names to Svartal, so the harness has to
/// answer that write and remember it: a name assigned in one call is what the
/// next listing reads back, which is the whole point of moving it off disk.
/// The write half of the fake Svartal: apply the PATCH the way the server
/// would, so the next listing tells the truth.
fn record_short_name(
    machines: &Arc<Mutex<Value>>,
    url: &str,
    short_name: Value,
) -> svartal::http::Response {
    // The one refusal worth exercising end to end: Svartal, not the CLI,
    // deciding a name cannot be had. The sentence has to survive the trip.
    if short_name == json!("taken") {
        return json_response(
            422,
            &json!({ "errors": { "short_name": ["is already the name of another machine you own"] } }),
        );
    }

    let segments: Vec<&str> = url.split('/').collect();
    let mut machines = machines.lock().unwrap();
    let rows = machines["data"].as_array_mut().expect("machines");

    // .../machines/<id>/environments/<environmentId>/short-name
    if let Some(position) = segments.iter().position(|segment| *segment == "environments") {
        let environment_id = segments[position + 1];
        for machine in rows.iter_mut() {
            for workspace in machine["environments"].as_array_mut().expect("environments") {
                if workspace["environmentId"] == json!(environment_id) {
                    workspace["shortName"] = short_name;
                    return json_response(200, &json!({ "data": workspace }));
                }
            }
        }
        return json_response(404, &json!({ "errors": { "detail": "Not found" } }));
    }

    // .../machines/<id>/short-name
    let machine_id = segments[segments.len() - 2];
    for machine in rows.iter_mut() {
        if machine["id"] == json!(machine_id) {
            machine["shortName"] = short_name;
            return json_response(200, &json!({ "data": machine }));
        }
    }
    json_response(404, &json!({ "errors": { "detail": "Not found" } }))
}

struct Harness {
    fixture: Value,
    directory: TempDir,
    machines: Arc<Mutex<Value>>,
}

impl Harness {
    fn new(tag: &str) -> Self {
        Self {
            fixture: fixture("oidc.json"),
            directory: TempDir::new(tag),
            machines: Arc::new(Mutex::new(serde_json::from_str(MACHINES_BODY).unwrap())),
        }
    }

    /// The short name Svartal now holds for one workspace.
    fn recorded_workspace_name(&self, environment_id: &str) -> Option<String> {
        let machines = self.machines.lock().unwrap();
        for machine in machines["data"].as_array()? {
            for workspace in machine["environments"].as_array()? {
                if workspace["environmentId"] == json!(environment_id) {
                    return workspace["shortName"].as_str().map(str::to_string);
                }
            }
        }
        None
    }

    fn recorded_machine_name(&self, machine_id: &str) -> Option<String> {
        let machines = self.machines.lock().unwrap();
        machines["data"]
            .as_array()?
            .iter()
            .find(|machine| machine["id"] == json!(machine_id))?["shortName"]
            .as_str()
            .map(str::to_string)
    }

    fn run(
        &self,
        command: impl FnOnce(&Context<'_>, &mut dyn std::io::Write) -> Result<(), commands::CliError>,
    ) -> (Result<(), commands::CliError>, String) {
        let fixture = self.fixture.clone();
        let issuer = fixture["issuer"].as_str().unwrap().to_string();
        let relay = fixture["relayUrl"].as_str().unwrap().to_string();
        let machines = Arc::clone(&self.machines);
        let http = FakeTransport::new(move |request| {
            let url = request.url.as_str();
            if url == format!("{issuer}/.well-known/openid-configuration") {
                return json_response(200, &fixture["discovery"]);
            }
            if url == format!("{issuer}/.well-known/jwks.json") {
                return json_response(200, &fixture["jwks"]);
            }
            if url == format!("{issuer}/api/v1/client/machines") {
                return json_response(200, &machines.lock().unwrap().clone());
            }
            if url == format!("{relay}/v1/environments") {
                return json_response(200, &serde_json::from_str(ENVIRONMENTS_BODY).unwrap());
            }
            if request.method == "PATCH" && url.ends_with("/short-name") {
                let short_name = match &request.body {
                    Some(svartal::http::Body::Json(body)) => body["short_name"].clone(),
                    _ => Value::Null,
                };
                return record_short_name(&machines, url, short_name);
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
        harness.run(|context, out| commands::name(context, out, "web", "Primary", false));
    outcome.unwrap();
    assert_eq!(output.trim(), "web is Primary (env-primary).");
    // Svartal holds it, not this computer: that is what makes the same word
    // read the same way in the web app and on another laptop.
    assert_eq!(harness.recorded_workspace_name("env-primary").as_deref(), Some("web"));
    // Mirrored locally so shell completion still works with no network, but
    // Svartal is the record.
    assert_eq!(harness.names().environment_of("web"), Some("env-primary"));

    // Naming it again through the name it already has is a no-op, not an error.
    let (outcome, _) = harness.run(|context, out| commands::name(context, out, "web", "web", false));
    outcome.unwrap();
    assert_eq!(harness.recorded_workspace_name("env-primary").as_deref(), Some("web"));
}

#[test]
fn a_machine_takes_a_name_of_its_own() {
    let harness = Harness::new("machine-name");
    let (outcome, output) =
        harness.run(|context, out| commands::name(context, out, "box", "workbench", true));
    outcome.unwrap();
    assert_eq!(output.trim(), "box is the machine workbench.");
    assert_eq!(harness.recorded_machine_name("machine-1").as_deref(), Some("box"));

    // Renaming says what it displaced, so the old word is not silently gone.
    let (outcome, output) =
        harness.run(|context, out| commands::name(context, out, "desk", "box", true));
    outcome.unwrap();
    assert!(output.contains("It used to be box."));
    assert_eq!(harness.recorded_machine_name("machine-1").as_deref(), Some("desk"));

    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "web", "nowhere", true));
    assert!(outcome.unwrap_err().to_string().contains("No machine called nowhere"));
}

#[test]
fn a_machine_reads_by_its_short_name_with_the_hostname_kept_beside_it() {
    let harness = Harness::new("machine-cell");
    harness.run(|context, out| commands::name(context, out, "box", "workbench", true)).0.unwrap();

    let (outcome, output) = harness.run(|context, out| commands::machines(context, out, false, false));
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("MACHINE"));
    // Both things, the chosen word first. Nothing a person already recognised
    // disappears when somebody names the box.
    assert!(lines[1].starts_with("box (workbench)"), "{}", lines[1]);
    // The heartbeat column no longer shares its header with the machine column.
    assert!(lines[0].contains("HEARTBEAT"));
    assert_eq!(lines[0].matches("MACHINE").count(), 1);
}

#[test]
fn a_name_svartal_holds_beats_one_this_computer_remembers() {
    let harness = Harness::new("precedence");
    // A name from before Svartal held them, pointing at the second workspace.
    let mut local = Shortnames::new();
    local.assign("web", "env-second").unwrap();
    write_shortnames(harness.directory.path(), &local).unwrap();

    let (outcome, output) =
        harness.run(|context, out| commands::name(context, out, "web", "Primary", false));
    outcome.unwrap();
    assert!(output.contains("web used to mean env-second."));

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, true, false));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let rows = parsed["environments"].as_array().unwrap();
    assert_eq!(rows[0]["environmentId"], json!("env-primary"));
    assert_eq!(rows[0]["shortname"], json!("web"));
    // The word now means the workspace Svartal says it means, in the cache too.
    assert_eq!(rows[1]["shortname"], Value::Null);
    assert_eq!(harness.names().environment_of("web"), Some("env-primary"));
}

#[test]
fn name_refuses_a_word_that_is_not_a_name_or_that_could_never_be_used() {
    let harness = Harness::new("refuse");
    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "Web Box", "Primary", false));
    assert!(outcome.unwrap_err().to_string().contains("is not a usable name"));

    // A workspace id always wins resolution, so a name shaped like one would
    // be recorded and then never used.
    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "env-second", "Primary", false));
    assert!(outcome.unwrap_err().to_string().contains("already a workspace id"));

    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "web", "nowhere", false));
    let message = outcome.unwrap_err().to_string();
    assert!(message.contains("No workspace called nowhere"));
    assert!(message.contains("SHORTNAME"), "the listing is offered with the refusal");

    assert!(harness.names().is_empty());
    assert_eq!(harness.recorded_workspace_name("env-primary"), None);
}

#[test]
fn name_lists_what_is_stored_and_remove_forgets_one() {
    let harness = Harness::new("list");
    let (outcome, output) = harness.run(commands::list_names);
    outcome.unwrap();
    assert!(output.contains("No names yet"));

    harness.run(|context, out| commands::name(context, out, "web", "Primary", false)).0.unwrap();
    harness.run(|context, out| commands::name(context, out, "box", "workbench", true)).0.unwrap();
    let (outcome, output) = harness.run(commands::list_names);
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(output.contains("box") && output.contains("machine") && output.contains("workbench"));
    assert!(output.contains("web") && output.contains("env-primary"));

    let (outcome, output) = harness.run(|context, out| commands::remove_name(context, out, "web"));
    outcome.unwrap();
    assert_eq!(output.trim(), "web is no longer a name for env-primary.");
    assert_eq!(harness.recorded_workspace_name("env-primary"), None);
    assert_eq!(harness.names().environment_of("web"), None);

    let (outcome, output) = harness.run(|context, out| commands::remove_name(context, out, "box"));
    outcome.unwrap();
    assert_eq!(output.trim(), "box is no longer a name for the machine workbench.");
    assert_eq!(harness.recorded_machine_name("machine-1"), None);

    let (outcome, _) = harness.run(|context, out| commands::remove_name(context, out, "web"));
    assert!(outcome.unwrap_err().to_string().contains("There is nothing named web"));
}

#[test]
fn a_refusal_from_svartal_is_repeated_in_the_words_svartal_used() {
    let harness = Harness::new("refusal-passthrough");
    let (outcome, _) =
        harness.run(|context, out| commands::name(context, out, "taken", "Primary", false));

    // Not "Svartal returned HTTP 422": a name is refused for reasons a person
    // can act on, and the sentence saying which is the point.
    let message = outcome.unwrap_err().to_string();
    assert!(message.contains("That name is already the name of another machine you own."), "{message}");
    // Nothing recorded anywhere, including the local cache.
    assert_eq!(harness.recorded_workspace_name("env-primary"), None);
    assert!(harness.names().is_empty());
}

#[test]
fn a_name_left_on_this_computer_is_listed_apart_and_can_still_be_forgotten() {
    let harness = Harness::new("local-leftover");
    let mut local = Shortnames::new();
    local.assign("old", "env-second").unwrap();
    write_shortnames(harness.directory.path(), &local).unwrap();

    let (outcome, output) = harness.run(commands::list_names);
    outcome.unwrap();
    assert!(output.contains("visible to nobody else"));
    assert!(output.contains("old") && output.contains("env-second"));

    let (outcome, output) = harness.run(|context, out| commands::remove_name(context, out, "old"));
    outcome.unwrap();
    assert_eq!(output.trim(), "old is no longer a name for env-second.");
    assert!(harness.names().is_empty());
}

#[test]
fn envs_prints_the_short_name_column_and_the_same_note_machines_prints() {
    let harness = Harness::new("envs");
    harness.run(|context, out| commands::name(context, out, "web", "Primary", false)).0.unwrap();

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, false, false));
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    assert!(lines[0].starts_with("SHORTNAME"));
    assert!(lines[1].starts_with("web") && lines[1].contains("env-primary"));
    assert!(lines[2].starts_with("-") && lines[2].contains("env-second"));
    assert_eq!(lines.last().copied().unwrap(), svartal::view::MACHINE_STATE_NOTE);

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, true, false));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    let rows = parsed["environments"].as_array().unwrap();
    assert_eq!(rows[0]["shortname"], json!("web"));
    assert_eq!(rows[0]["environmentId"], json!("env-primary"));
    assert_eq!(rows[1]["shortname"], Value::Null);
}

#[test]
fn envs_is_your_workspaces_and_all_names_who_the_others_belong_to() {
    let harness = Harness::new("envs-owner");

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, false, false));
    outcome.unwrap();
    assert!(output.contains("env-primary") && output.contains("env-second"));
    assert!(!output.contains("env-theirs"), "the second account's workspace is not yours");
    assert!(!output.contains("OWNER"));

    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, false, true));
    outcome.unwrap();
    let lines: Vec<&str> = output.lines().collect();
    // SHORTNAME, WORKSPACE, WORKSPACE ID, MACHINE, KIND, OWNER, … — the
    // header's own "WORKSPACE ID" is two words, so only the rows are counted.
    let owner_of = |line: &str| line.split_whitespace().nth(5).unwrap().to_string();
    assert!(lines[0].contains("OWNER"));
    assert!(lines[1].contains("env-primary"));
    assert_eq!(owner_of(lines[1]), "person");
    // A workspace Svartal named no owner for keeps a dash there.
    assert!(lines[2].contains("env-second"));
    assert_eq!(owner_of(lines[2]), "-");
    assert!(lines[3].contains("env-theirs"));
    assert_eq!(owner_of(lines[3]), "other");

    // `--json` is every row, with the owner, whatever `--all` says.
    let (outcome, output) = harness.run(|context, out| commands::envs(context, out, true, false));
    outcome.unwrap();
    let parsed: Value = serde_json::from_str(&output).unwrap();
    assert_eq!(
        parsed["environments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| (row["environmentId"].clone(), row["owner"].clone()))
            .collect::<Vec<_>>(),
        vec![
            (json!("env-primary"), json!("person")),
            (json!("env-second"), Value::Null),
            (json!("env-theirs"), json!("other")),
        ]
    );
}

#[test]
fn a_shell_target_can_be_a_short_name() {
    let harness = Harness::new("shell-target");
    // The cache resolves on its own, which is what makes `sv shell web` work
    // before the listing has been fetched.
    let mut local = Shortnames::new();
    local.assign("web", "env-primary").unwrap();
    write_shortnames(harness.directory.path(), &local).unwrap();
    let names = shortnames::read_shortnames(harness.directory.path()).unwrap();
    let target = svartal::target::select_target(&view(), &names, Some("web")).unwrap();
    assert_eq!(target.environment_id, "env-primary");
    assert_eq!(target.label, "Primary");
    drop(harness);
}
