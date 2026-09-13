//! `sv host up|status|down`: this computer as a Svartal machine.
//!
//! The engine is a fake that records every docker call and answers like a
//! real one would; the control plane is a routing function that walks the
//! workspace through requested → provisioning → ready. What the tests pin is
//! what would hurt: the enrollment token never in argv and gone from disk
//! afterwards, the four mounts on the container, the machine record reused
//! on a second `up`, and the sentences a person reads when it fails.

mod common;

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::browser::NoBrowser;
use svartal::http::HttpTransport;
use svartal::commands::{self, Context};
use svartal::config::resolve_config;
use svartal::host::{self, Docker, DockerOutput};
use svartal::store::MemoryTokenStorage;

const MACHINE_ID: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const TOKEN: &str = "svartal-enroll-one-time-secret-value";
const IMAGE_REF: &str = "ghcr.io/x/k3@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// The engine: every call recorded, the env-file a `run` was handed copied at
/// that moment (so a test can see what the container got even though the
/// file is deleted right after).
struct FakeDocker {
    calls: Mutex<Vec<Vec<String>>>,
    stdin: Mutex<Vec<String>>,
    env_files: Mutex<Vec<String>>,
    containers: Mutex<BTreeMap<String, bool>>,
    engine_up: bool,
}

impl FakeDocker {
    fn new(engine_up: bool) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            stdin: Mutex::new(Vec::new()),
            env_files: Mutex::new(Vec::new()),
            containers: Mutex::new(BTreeMap::new()),
            engine_up,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().iter().map(|call| call.join(" ")).collect()
    }

    /// A container the engine already has before the command runs.
    fn already_running(&self, container: &str) {
        self.containers.lock().unwrap().insert(container.to_string(), true);
    }

    fn container_names(&self) -> Vec<String> {
        self.containers.lock().unwrap().keys().cloned().collect()
    }
}

impl Docker for FakeDocker {
    fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<DockerOutput, String> {
        self.calls.lock().unwrap().push(args.to_vec());
        if let Some(bytes) = stdin {
            self.stdin.lock().unwrap().push(String::from_utf8_lossy(bytes).to_string());
        }
        let ok = |stdout: &str| Ok(DockerOutput { success: true, stdout: stdout.to_string(), stderr: String::new() });
        match args.first().map(String::as_str) {
            Some("info") if self.engine_up => ok("29.4.0\n"),
            Some("info") => Ok(DockerOutput { success: false, stdout: String::new(), stderr: "Cannot connect to the Docker daemon".into() }),
            // Every container is looked up by name, because two machines on
            // one computer are two containers.
            Some("inspect") => match args.last().and_then(|name| self.containers.lock().unwrap().get(name).copied()) {
                Some(running) => ok(if running { "true\n" } else { "false\n" }),
                None => Ok(DockerOutput { success: false, stdout: String::new(), stderr: "No such object".into() }),
            },
            Some("pull") => ok("Status: Downloaded"),
            Some("rm") => {
                let name = args.last().cloned().unwrap_or_default();
                self.containers.lock().unwrap().remove(&name);
                ok(&format!("{name}\n"))
            }
            Some("run") if args.contains(&"--entrypoint".to_string()) => ok(""),
            Some("run") => {
                let env_file = args
                    .iter()
                    .position(|argument| argument == "--env-file")
                    .and_then(|index| args.get(index + 1))
                    .map(|path| std::fs::read_to_string(path).unwrap_or_default())
                    .unwrap_or_default();
                self.env_files.lock().unwrap().push(env_file);
                let name = args
                    .iter()
                    .position(|argument| argument == "--name")
                    .and_then(|index| args.get(index + 1))
                    .cloned()
                    .unwrap_or_default();
                self.containers.lock().unwrap().insert(name, true);
                ok("c0ffee\n")
            }
            Some("logs") => ok("{\"event\":\"host_serving\"}\n"),
            Some("volume") => ok(""),
            other => Err(format!("unexpected docker call: {other:?}")),
        }
    }
}

/// One answer the control plane gives a poll: the lifecycle state, and after
/// a `/` whether Svartal also said the workspace is linked to the caller.
/// A bare `"ready"` is a Svartal old enough never to say, which is the
/// compatibility case.
fn poll_answer(answer: &str) -> (&str, Option<bool>) {
    match answer.split_once('/') {
        Some((state, "linked")) => (state, Some(true)),
        Some((state, "unlinked")) => (state, Some(false)),
        _ => (answer, None),
    }
}

/// The control plane: identity endpoints from the fixture, plus the two
/// host-machine routes. `states` is what successive GETs answer.
fn transport(fixture: Value, states: Vec<&'static str>, with_release: bool) -> FakeTransport {
    let issuer = fixture["issuer"].as_str().unwrap().to_string();
    let polls = Mutex::new(0usize);
    FakeTransport::new(move |request| {
        let url = request.url.as_str();
        if url == format!("{issuer}/.well-known/openid-configuration") {
            return json_response(200, &fixture["discovery"]);
        }
        if url == format!("{issuer}/.well-known/jwks.json") {
            return json_response(200, &fixture["jwks"]);
        }
        let release = if with_release { json!({ "imageRef": IMAGE_REF, "version": "v9" }) } else { Value::Null };
        if url.ends_with("/api/v1/client/host-machines") && request.method == "POST" {
            let body = match &request.body {
                Some(svartal::http::Body::Json(value)) => value.clone(),
                _ => Value::Null,
            };
            return json_response(
                201,
                &json!({ "data": {
                    "machine": { "id": MACHINE_ID, "name": body["name"].as_str().unwrap_or("laptop") },
                    "enrollmentToken": TOKEN,
                    "workspaceIntent": { "lifecycleState": "requested", "environmentId": null, "lastError": {} },
                    "release": release,
                    "echo": body,
                }}),
            );
        }
        if url.ends_with(&format!("/api/v1/client/host-machines/{MACHINE_ID}")) {
            let mut seen = polls.lock().unwrap();
            let answer = states.get(*seen).copied().unwrap_or_else(|| states.last().copied().unwrap_or("ready"));
            *seen += 1;
            let (state, linked) = poll_answer(answer);
            let (environment, error) = match state {
                "ready" => (json!("environment-1234"), json!({})),
                "failed" => (Value::Null, json!({ "code": "host_capacity_disk" })),
                _ => (Value::Null, json!({})),
            };
            let mut data = json!({
                "machine": { "id": MACHINE_ID, "name": "laptop" },
                "workspaceIntent": { "lifecycleState": state, "environmentId": environment, "lastError": error },
                "release": release,
            });
            // An older Svartal has no `linked` key at all, so the tests that
            // do not ask for one get that server.
            if let Some(linked) = linked {
                data["linked"] = json!(linked);
            }
            return json_response(200, &json!({ "data": data }));
        }
        json_response(404, &json!({ "error": "unexpected" }))
    })
}

struct Run {
    outcome: Result<(), commands::CliError>,
    output: String,
    urls: Vec<String>,
    posted: Vec<Value>,
}

/// `HOME` and the poll interval are process environment, so the runs in this
/// binary take turns: a parallel test would otherwise point the registry
/// lookup at somebody else's directory.
static ENVIRONMENT: Mutex<()> = Mutex::new(());

fn run<F>(signed_in: bool, docker: &FakeDocker, states: Vec<&'static str>, with_release: bool, state_dir: &std::path::Path, command: F) -> Run
where
    F: FnOnce(&Context<'_>, &mut dyn std::io::Write, &dyn Docker) -> Result<(), commands::CliError>,
{
    run_http(signed_in, docker, transport(fixture("oidc.json"), states, with_release), state_dir, command)
}

fn run_http<F>(signed_in: bool, docker: &FakeDocker, http: FakeTransport, state_dir: &std::path::Path, command: F) -> Run
where
    F: FnOnce(&Context<'_>, &mut dyn std::io::Write, &dyn Docker) -> Result<(), commands::CliError>,
{
    let _turn = ENVIRONMENT.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    // SAFETY: the tests here set the same values; the poll interval only
    // shortens the wait and HOME only points the registry lookup at a
    // directory this test controls.
    unsafe {
        std::env::set_var("SVARTAL_HOST_POLL_MS", "0");
        std::env::set_var("HOME", state_dir);
    }
    let fixture = fixture("oidc.json");
    let now = fixture["nowEpochMs"].as_i64().unwrap();
    let storage = if signed_in {
        MemoryTokenStorage::with_value(&fixture["storedTokens"].to_string())
    } else {
        MemoryTokenStorage::new()
    };
    let environment = [
        ("HOME".to_string(), state_dir.to_string_lossy().to_string()),
        ("SVARTAL_CONFIG_DIR".to_string(), state_dir.join("config").to_string_lossy().to_string()),
        ("SVARTAL_ISSUER".to_string(), fixture["issuer"].as_str().unwrap().to_string()),
        ("SVARTAL_RELAY_URL".to_string(), fixture["relayUrl"].as_str().unwrap().to_string()),
    ]
    .into_iter()
    .collect();
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
    let outcome = command(&context, &mut out, docker);
    let posted = http
        .requests()
        .into_iter()
        .filter(|request| request.method == "POST" && request.url.ends_with("/host-machines"))
        .filter_map(|request| match request.body {
            Some(svartal::http::Body::Json(value)) => Some(value),
            _ => None,
        })
        .collect();
    Run { outcome, output: String::from_utf8(out).unwrap(), urls: http.urls(), posted }
}

#[test]
fn up_registers_starts_the_container_and_waits_for_the_workspace() {
    let dir = TempDir::new("host-up");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["requested", "provisioning", "ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("ghcr.io/x/svartal-host:test"), None)
    });
    run.outcome.unwrap();
    assert!(run.output.contains("Registering this computer with Svartal as "), "{}", run.output);
    assert!(run.output.contains("Waiting for the machine"), "{}", run.output);
    assert!(run.output.contains("Creating your workspace container"), "{}", run.output);
    assert!(run.output.contains("Your workspace is ready."), "{}", run.output);
    assert!(run.output.contains("sv envs"), "{}", run.output);

    // One registration, then polls until ready.
    assert_eq!(run.posted.len(), 1);
    // Nothing was registered before the image was in hand.
    let calls = docker.calls();
    let pulled = calls.iter().position(|call| call.starts_with("pull ")).expect("a pull");
    assert!(pulled == 1 || pulled == 0, "the pull must come first: {calls:?}");
    assert!(run.posted[0].get("machine_id").is_none(), "a first up must not name a machine");
    assert_eq!(run.urls.iter().filter(|url| url.ends_with(MACHINE_ID)).count(), 3);

    // The container: pulled, run with the four mounts and the env-file, and
    // nothing secret in argv.
    assert!(calls.iter().any(|call| call == "pull ghcr.io/x/svartal-host:test"), "{calls:?}");
    let started = calls.iter().find(|call| call.starts_with("run -d")).expect("a run");
    for mount in [
        "-v /var/run/docker.sock:/var/run/docker.sock",
        "-v svartal-host-config:/etc/svartal",
        "-v svartal-host-state:/var/lib/svartal",
        "-v svartal-run:/run/svartal",
        "--name svartal-host --restart unless-stopped",
    ] {
        assert!(started.contains(mount), "{started}");
    }
    assert!(!calls.iter().any(|call| call.contains(TOKEN)), "the token reached argv: {calls:?}");

    // The env-file the container was handed carried the token and the image;
    // it is gone from disk now.
    let env_files = docker.env_files.lock().unwrap().clone();
    assert_eq!(env_files.len(), 1);
    assert!(env_files[0].contains(&format!("SVARTAL_ENROLLMENT_TOKEN={TOKEN}\n")));
    assert!(env_files[0].contains(&format!("SVARTAL_MACHINE_ID={MACHINE_ID}\n")));
    assert!(env_files[0].contains(&format!("SVARTAL_MANAGED_IMAGE_REF={IMAGE_REF}\n")));
    assert!(!dir.path().join("config/host.env").exists(), "the env-file stayed on disk");

    // No registry login on this computer: said so, and no credential copied.
    assert!(run.output.contains("No ghcr.io login"), "{}", run.output);
    assert!(docker.stdin.lock().unwrap().is_empty());

    // The machine is remembered for next time.
    let record = host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).expect("a host record");
    assert_eq!(record.machine_id, MACHINE_ID);
    assert_eq!(record.image, "ghcr.io/x/svartal-host:test");
}

#[test]
fn a_second_up_reuses_the_machine_and_replaces_the_container() {
    let dir = TempDir::new("host-up-again");
    host::write_record(
        &dir.path().join("config"),
        &host::Instance::default_instance(),
        &host::HostRecord { machine_id: MACHINE_ID.into(), machine_name: "laptop".into(), machine_short_name: None, image: "ghcr.io/x/svartal-host:test".into() },
    )
    .unwrap();
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, None, None)
    });
    run.outcome.unwrap();
    assert_eq!(run.posted[0]["machine_id"], MACHINE_ID);
    assert_eq!(run.posted[0]["name"], "laptop");
    let calls = docker.calls();
    let removed = calls.iter().position(|call| call == "rm -f svartal-host").expect("the old container removed");
    let started = calls.iter().position(|call| call.starts_with("run -d")).expect("a new run");
    assert!(removed < started, "{calls:?}");
    assert!(calls[started].ends_with("ghcr.io/x/svartal-host:test"), "the remembered image is used: {}", calls[started]);
}

#[test]
fn a_registry_login_on_this_computer_is_copied_into_the_machine() {
    let dir = TempDir::new("host-up-registry");
    std::fs::create_dir_all(dir.path().join(".docker")).unwrap();
    std::fs::write(dir.path().join(".docker/config.json"), r#"{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQ="}}}"#).unwrap();
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("ghcr.io/x/svartal-host:test"), None)
    });
    run.outcome.unwrap();
    let stdin = docker.stdin.lock().unwrap().clone();
    assert_eq!(stdin, vec![r#"{"auths":{"ghcr.io":{"auth":"dXNlcjpwYXQ="}}}"#.to_string()]);
    let helper = docker.calls().into_iter().find(|call| call.contains("--entrypoint sh")).expect("the copy");
    assert!(helper.contains("-v svartal-host-config:/etc/svartal"), "{helper}");
    assert!(!helper.contains("dXNlcjpwYXQ="), "the credential reached argv");
    let env_files = docker.env_files.lock().unwrap().clone();
    assert!(env_files[0].contains("DOCKER_CONFIG=/etc/svartal/docker\n"));
    assert!(!run.output.contains("No ghcr.io login"));
}

#[test]
fn a_failed_workspace_names_the_cause_and_the_log() {
    let dir = TempDir::new("host-up-failed");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["requested", "failed"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), None)
    });
    let error = run.outcome.unwrap_err().to_string();
    assert!(error.contains("host_capacity_disk"), "{error}");
    assert!(error.contains("host_serving"), "the log was not shown: {error}");
    assert!(error.contains("sv host up"), "{error}");
}

/// Success means the person can see the machine they just started. A
/// workspace Svartal reports as ready but not linked to the account that
/// asked is the laptop case: `up` used to say "ready" while the same
/// account's `sv machines` said `not linked`.
#[test]
fn up_waits_for_the_workspace_to_become_visible_to_your_account() {
    let dir = TempDir::new("host-up-unlinked");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["ready/unlinked", "ready/linked"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), None)
    });
    run.outcome.unwrap();
    assert_eq!(
        run.output.matches("Your workspace is running but not visible to your account yet").count(),
        1,
        "{}",
        run.output
    );
    assert!(run.output.contains("Your workspace is ready."), "{}", run.output);
    assert!(run.output.contains("sv envs"), "{}", run.output);
    // It kept polling, which is what asks Svartal to repair the link.
    assert_eq!(run.urls.iter().filter(|url| url.ends_with(MACHINE_ID)).count(), 2, "{:?}", run.urls);
}

/// A Svartal that never says whether the workspace is linked is the one this
/// release replaces; `up` must not wait on an answer it will never get.
#[test]
fn a_server_that_says_nothing_about_linking_still_finishes_at_ready() {
    let dir = TempDir::new("host-up-no-linked-key");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), None)
    });
    run.outcome.unwrap();
    assert!(run.output.contains("Your workspace is ready."), "{}", run.output);
    assert!(!run.output.contains("not visible to your account"), "{}", run.output);
    assert_eq!(run.urls.iter().filter(|url| url.ends_with(MACHINE_ID)).count(), 1, "{:?}", run.urls);
}

/// `relinking` is Svartal repairing the link: a state to wait through, said
/// in words, not a failure.
#[test]
fn relinking_is_a_state_up_waits_through() {
    let dir = TempDir::new("host-up-relinking");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["relinking/unlinked", "ready/linked"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), None)
    });
    run.outcome.unwrap();
    assert!(run.output.contains("Linking your workspace to your account"), "{}", run.output);
    assert!(run.output.contains("Your workspace is ready."), "{}", run.output);
}

/// `sv host status` answers the question the owner actually asks — can I see
/// this machine — and says nothing when Svartal did not say.
#[test]
fn status_says_whether_the_workspace_is_visible_to_your_account() {
    let dir = TempDir::new("host-status-linked");
    record(&dir, &host::Instance::default_instance(), "laptop");
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);

    let visible = run(true, &docker, vec!["ready/linked"], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, None)
    });
    visible.outcome.unwrap();
    assert!(visible.output.contains("Visible to your account in Ivaldi."), "{}", visible.output);

    let unseen = run(true, &docker, vec!["ready/unlinked"], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, None)
    });
    unseen.outcome.unwrap();
    assert!(unseen.output.contains("Not visible to your account yet; Svartal is re-linking it."), "{}", unseen.output);

    let unsaid = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, None)
    });
    unsaid.outcome.unwrap();
    assert!(!unsaid.output.contains("visible to your account"), "{}", unsaid.output);
    assert!(unsaid.output.contains("Your workspace is ready."), "{}", unsaid.output);
}

#[test]
fn no_engine_no_release_and_no_session_each_get_their_sentence() {
    let dir = TempDir::new("host-up-refusals");
    let down = FakeDocker::new(false);
    let run_down = run(true, &down, vec![], true, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None, None, None));
    assert!(run_down.outcome.unwrap_err().to_string().contains("Docker is not running"));
    assert!(run_down.posted.is_empty(), "registered a machine with no engine");

    let up = FakeDocker::new(true);
    let run_none = run(true, &up, vec![], false, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None, None, None));
    assert!(run_none.outcome.unwrap_err().to_string().contains("no published workspace image"));
    assert!(!up.calls().iter().any(|call| call.starts_with("run")), "started a machine with nothing to run");

    let run_out = run(false, &up, vec![], true, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None, None, None));
    assert_eq!(run_out.outcome.unwrap_err().to_string(), commands::NOT_SIGNED_IN);
}

#[test]
fn purge_keeps_the_registration_and_the_next_up_reuses_it() {
    let dir = TempDir::new("host-status-down");
    let docker = FakeDocker::new(true);
    let run_before = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_status(context, out, docker, None));
    run_before.outcome.unwrap();
    assert!(run_before.output.contains("not a Svartal machine"), "{}", run_before.output);

    host::write_record(
        &dir.path().join("config"),
        &host::Instance::default_instance(),
        &host::HostRecord { machine_id: MACHINE_ID.into(), machine_name: "laptop".into(), machine_short_name: None, image: "img".into() },
    )
    .unwrap();
    docker.already_running(host::CONTAINER_NAME);
    let run_status = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| commands::host_status(context, out, docker, None));
    run_status.outcome.unwrap();
    assert!(run_status.output.contains("container svartal-host is running"), "{}", run_status.output);
    assert!(run_status.output.contains("Your workspace is ready."), "{}", run_status.output);
    assert!(run_status.output.contains("environment-1234"), "{}", run_status.output);

    let run_down = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_down(context, out, docker, false, None));
    run_down.outcome.unwrap();
    assert!(run_down.output.contains("removed"), "{}", run_down.output);
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_some(), "a plain down forgot the machine");

    let run_purge = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_down(context, out, docker, true, None));
    run_purge.outcome.unwrap();
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_some(), "purge forgot the account registration");
    assert!(run_purge.output.contains("account registration was kept"));
    let next = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None, None, None));
    next.outcome.unwrap();
    assert_eq!(next.posted.len(), 1);
    assert_eq!(next.posted[0]["machine_id"], MACHINE_ID);
    let calls = docker.calls();
    for volume in ["svartal-host-config", "svartal-host-state", "svartal-run"] {
        assert!(calls.iter().any(|call| call == &format!("volume rm -f {volume}")), "{calls:?}");
    }
}

#[test]
fn a_pull_that_fails_leaves_no_machine_on_the_account() {
    let dir = TempDir::new("host-up-pull-fails");
    struct NoImage(FakeDocker);
    impl Docker for NoImage {
        fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<DockerOutput, String> {
            if args.first().map(String::as_str) == Some("pull") {
                self.0.calls.lock().unwrap().push(args.to_vec());
                return Ok(DockerOutput {
                    success: false,
                    stdout: String::new(),
                    stderr: "error from registry: unauthorized".into(),
                });
            }
            self.0.run(args, stdin)
        }
    }
    let docker = NoImage(FakeDocker::new(true));
    let run = run(true, &docker.0, vec!["ready"], true, dir.path(), |context, out, _| {
        commands::host_up(context, out, &docker, None, Some("ghcr.io/x/svartal-host:test"), None)
    });
    let error = run.outcome.unwrap_err().to_string();
    assert!(error.contains("Could not pull"), "{error}");
    assert!(error.contains("docker login ghcr.io"), "{error}");
    // Nothing was created: no registration call, no local record.
    assert!(run.posted.is_empty(), "a machine was registered for a run that could not start");
    assert!(!run.urls.iter().any(|url| url.contains("host-machines")), "{:?}", run.urls);
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_none());
}

#[test]
fn a_given_name_reaches_svartal_and_is_cleaned_first() {
    let dir = TempDir::new("host-up-name");
    let docker = FakeDocker::new(true);
    let first_run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, Some("  work laptop\n "), Some("img"), None)
    });
    first_run.outcome.unwrap();
    assert_eq!(first_run.posted[0]["name"], "work laptop");

    // A later run without --name keeps the recorded name, and one with a new
    // name sends it alongside the machine id, which is how a rename happens.
    let again_run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), None)
    });
    again_run.outcome.unwrap();
    assert_eq!(again_run.posted[0]["name"], "work laptop", "the recorded name must survive a plain up");
    let renamed_run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, Some("kitchen mac"), Some("img"), None)
    });
    renamed_run.outcome.unwrap();
    assert_eq!(renamed_run.posted[0]["name"], "kitchen mac");
    assert_eq!(renamed_run.posted[0]["machine_id"], MACHINE_ID);
}

/// Two machines on one computer is the reason `--instance` exists, so what
/// these pin is separation: a named machine touches nothing the default one
/// owns, and neither can be reached by leaving the word out.
fn record(dir: &TempDir, instance: &host::Instance, machine_name: &str) {
    host::write_record(
        &dir.path().join("config"),
        instance,
        &host::HostRecord { machine_id: MACHINE_ID.into(), machine_name: machine_name.into(), machine_short_name: None, image: "img".into() },
    )
    .unwrap();
}

fn instance(name: &str) -> host::Instance {
    host::Instance::parse(Some(name)).unwrap()
}

#[test]
fn a_named_instance_gets_its_own_container_volumes_and_record() {
    let dir = TempDir::new("host-up-instance");
    let docker = FakeDocker::new(true);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), Some("m3b"))
    });
    run.outcome.unwrap();
    let started = docker.calls().into_iter().find(|call| call.starts_with("run -d")).expect("a run");
    for part in [
        "--name svartal-host-m3b --restart unless-stopped",
        "-v svartal-host-m3b-config:/etc/svartal",
        "-v svartal-host-m3b-state:/var/lib/svartal",
        "-v svartal-run-m3b:/run/svartal",
    ] {
        assert!(started.contains(part), "{started}");
    }
    assert!(run.output.contains("container svartal-host-m3b"), "{}", run.output);

    // The machine mounts these volumes into the containers it creates, so the
    // names it is told have to be its own.
    let env_files = docker.env_files.lock().unwrap().clone();
    assert!(env_files[0].contains("SVARTAL_STATE_VOLUME=svartal-host-m3b-state\n"), "{}", env_files[0]);
    assert!(env_files[0].contains("SVARTAL_RUN_VOLUME=svartal-run-m3b\n"), "{}", env_files[0]);

    // The record is the named one, and the default machine's is untouched.
    assert!(dir.path().join("config/host-m3b.json").exists());
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_none());
    assert_eq!(
        host::read_record(&dir.path().join("config"), &instance("m3b")).map(|record| record.machine_id),
        Some(MACHINE_ID.to_string())
    );
}

#[test]
fn starting_a_second_machine_leaves_the_first_ones_container_alone() {
    let dir = TempDir::new("host-up-second");
    record(&dir, &host::Instance::default_instance(), "laptop");
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, Some("img"), Some("b"))
    });
    run.outcome.unwrap();
    let calls = docker.calls();
    assert!(!calls.iter().any(|call| call == "rm -f svartal-host"), "the default machine was replaced: {calls:?}");
    assert_eq!(docker.container_names(), vec!["svartal-host".to_string(), "svartal-host-b".to_string()]);
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_some());
    assert!(host::read_record(&dir.path().join("config"), &instance("b")).is_some());
}

#[test]
fn an_instance_name_sv_cannot_use_is_refused_before_anything_happens() {
    let dir = TempDir::new("host-instance-refused");
    for name in ["M3B", "two words", "-leading", "", "under_score"] {
        let docker = FakeDocker::new(true);
        for outcome in [
            run(true, &docker, vec![], true, dir.path(), |context, out, docker| {
                commands::host_up(context, out, docker, None, Some("img"), Some(name))
            }),
            run(true, &docker, vec![], true, dir.path(), |context, out, docker| {
                commands::host_status(context, out, docker, Some(name))
            }),
            run(true, &docker, vec![], true, dir.path(), |context, out, docker| {
                commands::host_down(context, out, docker, false, Some(name))
            }),
        ] {
            let error = outcome.outcome.unwrap_err().to_string();
            assert!(error.contains(host::INSTANCE_NAME_RULE), "{error}");
            assert!(outcome.urls.is_empty(), "`{name}` reached Svartal: {:?}", outcome.urls);
        }
        assert!(docker.calls().is_empty(), "`{name}` reached docker: {:?}", docker.calls());
    }
}

#[test]
fn status_lists_every_machine_on_this_computer_and_one_when_asked() {
    let dir = TempDir::new("host-status-instances");
    record(&dir, &host::Instance::default_instance(), "laptop");
    record(&dir, &instance("m3b"), "second-machine");
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);
    docker.already_running("svartal-host-m3b");

    let all = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, None)
    });
    all.outcome.unwrap();
    assert!(all.output.contains("Machine laptop (") && all.output.contains("container svartal-host is running."), "{}", all.output);
    assert!(
        all.output.contains("Machine second-machine (") && all.output.contains("on instance m3b: container svartal-host-m3b is running."),
        "{}",
        all.output
    );

    let one = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, Some("m3b"))
    });
    one.outcome.unwrap();
    assert!(one.output.contains("container svartal-host-m3b is running."), "{}", one.output);
    assert!(!one.output.contains("container svartal-host is running."), "{}", one.output);

    // A machine that was never started here is said so in its own words.
    let missing = run(true, &docker, vec![], true, dir.path(), |context, out, docker| {
        commands::host_status(context, out, docker, Some("nope"))
    });
    missing.outcome.unwrap();
    assert!(missing.output.contains("`sv host up --instance nope`"), "{}", missing.output);
}

#[test]
fn down_with_an_instance_removes_only_that_machine() {
    let dir = TempDir::new("host-down-instance");
    record(&dir, &host::Instance::default_instance(), "laptop");
    record(&dir, &instance("m3b"), "second-machine");
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);
    docker.already_running("svartal-host-m3b");

    let down = run(true, &docker, vec![], true, dir.path(), |context, out, docker| {
        commands::host_down(context, out, docker, true, Some("m3b"))
    });
    down.outcome.unwrap();
    let calls = docker.calls();
    assert!(calls.iter().any(|call| call == "rm -f svartal-host-m3b"), "{calls:?}");
    assert!(!calls.iter().any(|call| call == "rm -f svartal-host"), "the default machine was removed too: {calls:?}");
    assert_eq!(docker.container_names(), vec!["svartal-host".to_string()]);
    for volume in ["svartal-host-m3b-config", "svartal-host-m3b-state", "svartal-run-m3b"] {
        assert!(calls.iter().any(|call| call == &format!("volume rm -f {volume}")), "{calls:?}");
    }
    for volume in ["svartal-host-config", "svartal-host-state", "svartal-run"] {
        assert!(!calls.iter().any(|call| call == &format!("volume rm -f {volume}")), "{calls:?}");
    }
    assert!(host::read_record(&dir.path().join("config"), &instance("m3b")).is_some());
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_some());
}


fn refusing_registration(statuses: Vec<u16>) -> FakeTransport {
    let inner = transport(fixture("oidc.json"), vec!["ready"], true);
    let statuses = Mutex::new(std::collections::VecDeque::from(statuses));
    FakeTransport::new(move |request| {
        if request.method == "POST" && request.url.ends_with("/host-machines")
            && let Some(status) = statuses.lock().unwrap().pop_front()
        {
            return json_response(status, &json!({"errors": {"name": ["is already the name of another machine you own"]}}));
        }
        inner.send(request.clone()).unwrap()
    })
}

#[test]
fn a_missing_registration_is_replaced_once_without_erasing_runtime_volumes() {
    let dir = TempDir::new("host-missing-registration");
    host::write_record(&dir.path().join("config"), &host::Instance::default_instance(), &host::HostRecord {
        machine_id: "missing-machine".into(), machine_name: "laptop".into(), machine_short_name: None, image: "img".into(),
    }).unwrap();
    let docker = FakeDocker::new(true);
    let result = run_http(true, &docker, refusing_registration(vec![404]), dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, None, None)
    });
    result.outcome.unwrap();
    assert_eq!(result.posted.len(), 2);
    assert_eq!(result.posted[0]["machine_id"], "missing-machine");
    assert!(result.posted[1].get("machine_id").is_none());
    assert_eq!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).unwrap().machine_id, MACHINE_ID);
    assert!(!docker.calls().iter().any(|call| call.starts_with("volume rm")));
    assert!(result.output.contains("registering this computer again"));
}

#[test]
fn registration_does_not_retry_other_refusals_or_a_first_registration_404() {
    for (existing, status) in [(true, 401), (true, 403), (true, 422), (true, 500), (false, 404)] {
        let dir = TempDir::new("host-registration-refused");
        if existing { record(&dir, &host::Instance::default_instance(), "laptop"); }
        let docker = FakeDocker::new(true);
        let result = run_http(true, &docker, refusing_registration(vec![status]), dir.path(), |context, out, docker| {
            commands::host_up(context, out, docker, None, None, None)
        });
        let error = result.outcome.unwrap_err().to_string();
        assert_eq!(result.posted.len(), 1);
        if status == 401 || status == 403 { assert!(error.contains("sv login"), "{error}"); }
        else {
            assert!(error.contains(&format!("HTTP {status}")), "{error}");
            assert!(error.contains("name is already the name of another machine you own"), "{error}");
        }
        assert!(!docker.calls().iter().any(|call| call.starts_with("run -d")));
    }
}

#[test]
fn a_failed_replacement_keeps_the_saved_registration_and_running_container() {
    let dir = TempDir::new("host-registration-retry-fails");
    record(&dir, &host::Instance::default_instance(), "laptop");
    let docker = FakeDocker::new(true);
    docker.already_running(host::CONTAINER_NAME);
    let result = run_http(true, &docker, refusing_registration(vec![404, 422]), dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None, None, None)
    });
    assert!(result.outcome.unwrap_err().to_string().contains("HTTP 422"));
    assert_eq!(result.posted.len(), 2);
    assert_eq!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).unwrap().machine_id, MACHINE_ID);
    assert!(!docker.calls().iter().any(|call| call.starts_with("rm ") || call.starts_with("volume rm")));
}

#[test]
fn a_volume_removal_failure_is_not_reported_as_a_successful_purge() {
    let dir = TempDir::new("host-purge-failed");
    record(&dir, &host::Instance::default_instance(), "laptop");
    struct VolumeInUse(FakeDocker);
    impl Docker for VolumeInUse {
        fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<DockerOutput, String> {
            if args.first().map(String::as_str) == Some("volume") {
                return Ok(DockerOutput { success: false, stdout: String::new(), stderr: "volume is in use".into() });
            }
            self.0.run(args, stdin)
        }
    }
    let docker = VolumeInUse(FakeDocker::new(true));
    let result = run(true, &docker.0, vec![], true, dir.path(), |context, out, _| {
        commands::host_down(context, out, &docker, true, None)
    });
    assert!(result.outcome.unwrap_err().to_string().contains("volume is in use"));
    assert!(!result.output.contains("volumes were deleted"));
    assert!(host::read_record(&dir.path().join("config"), &host::Instance::default_instance()).is_some());
}
