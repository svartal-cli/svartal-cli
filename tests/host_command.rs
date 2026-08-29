//! `sv host up|status|down`: this computer as a Svartal machine.
//!
//! The engine is a fake that records every docker call and answers like a
//! real one would; the control plane is a routing function that walks the
//! workspace through requested → provisioning → ready. What the tests pin is
//! what would hurt: the enrollment token never in argv and gone from disk
//! afterwards, the four mounts on the container, the machine record reused
//! on a second `up`, and the sentences a person reads when it fails.

mod common;

use std::sync::Mutex;

use serde_json::{Value, json};

use common::{FakeTransport, TempDir, fixture, json_response};
use svartal::browser::NoBrowser;
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
    running: Mutex<Option<bool>>,
    engine_up: bool,
}

impl FakeDocker {
    fn new(engine_up: bool) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            stdin: Mutex::new(Vec::new()),
            env_files: Mutex::new(Vec::new()),
            running: Mutex::new(None),
            engine_up,
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().iter().map(|call| call.join(" ")).collect()
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
            Some("inspect") => match *self.running.lock().unwrap() {
                Some(running) => ok(if running { "true\n" } else { "false\n" }),
                None => Ok(DockerOutput { success: false, stdout: String::new(), stderr: "No such object".into() }),
            },
            Some("pull") => ok("Status: Downloaded"),
            Some("rm") => {
                *self.running.lock().unwrap() = None;
                ok("svartal-host\n")
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
                *self.running.lock().unwrap() = Some(true);
                ok("c0ffee\n")
            }
            Some("logs") => ok("{\"event\":\"host_serving\"}\n"),
            Some("volume") => ok(""),
            other => Err(format!("unexpected docker call: {other:?}")),
        }
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
            let state = states.get(*seen).copied().unwrap_or_else(|| states.last().copied().unwrap_or("ready"));
            *seen += 1;
            let (environment, error) = match state {
                "ready" => (json!("environment-1234"), json!({})),
                "failed" => (Value::Null, json!({ "code": "host_capacity_disk" })),
                _ => (Value::Null, json!({})),
            };
            return json_response(
                200,
                &json!({ "data": {
                    "machine": { "id": MACHINE_ID, "name": "laptop" },
                    "workspaceIntent": { "lifecycleState": state, "environmentId": environment, "lastError": error },
                    "release": release,
                }}),
            );
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
    let http = transport(fixture.clone(), states, with_release);
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
        commands::host_up(context, out, docker, Some("ghcr.io/x/svartal-host:test"))
    });
    run.outcome.unwrap();
    assert!(run.output.contains("Registering this computer with Svartal as "), "{}", run.output);
    assert!(run.output.contains("Waiting for the machine"), "{}", run.output);
    assert!(run.output.contains("Creating your workspace container"), "{}", run.output);
    assert!(run.output.contains("Your workspace is ready."), "{}", run.output);
    assert!(run.output.contains("sv envs"), "{}", run.output);

    // One registration, then polls until ready.
    assert_eq!(run.posted.len(), 1);
    assert!(run.posted[0].get("machine_id").is_none(), "a first up must not name a machine");
    assert_eq!(run.urls.iter().filter(|url| url.ends_with(MACHINE_ID)).count(), 3);

    // The container: pulled, run with the four mounts and the env-file, and
    // nothing secret in argv.
    let calls = docker.calls();
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
    let record = host::read_record(&dir.path().join("config")).expect("a host record");
    assert_eq!(record.machine_id, MACHINE_ID);
    assert_eq!(record.image, "ghcr.io/x/svartal-host:test");
}

#[test]
fn a_second_up_reuses_the_machine_and_replaces_the_container() {
    let dir = TempDir::new("host-up-again");
    host::write_record(
        &dir.path().join("config"),
        &host::HostRecord { machine_id: MACHINE_ID.into(), machine_name: "laptop".into(), image: "ghcr.io/x/svartal-host:test".into() },
    )
    .unwrap();
    let docker = FakeDocker::new(true);
    *docker.running.lock().unwrap() = Some(true);
    let run = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| {
        commands::host_up(context, out, docker, None)
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
        commands::host_up(context, out, docker, Some("ghcr.io/x/svartal-host:test"))
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
        commands::host_up(context, out, docker, Some("img"))
    });
    let error = run.outcome.unwrap_err().to_string();
    assert!(error.contains("host_capacity_disk"), "{error}");
    assert!(error.contains("host_serving"), "the log was not shown: {error}");
    assert!(error.contains("sv host up"), "{error}");
}

#[test]
fn no_engine_no_release_and_no_session_each_get_their_sentence() {
    let dir = TempDir::new("host-up-refusals");
    let down = FakeDocker::new(false);
    let run_down = run(true, &down, vec![], true, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None));
    assert!(run_down.outcome.unwrap_err().to_string().contains("Docker is not running"));
    assert!(run_down.posted.is_empty(), "registered a machine with no engine");

    let up = FakeDocker::new(true);
    let run_none = run(true, &up, vec![], false, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None));
    assert!(run_none.outcome.unwrap_err().to_string().contains("no published workspace image"));
    assert!(!up.calls().iter().any(|call| call.starts_with("run")), "started a machine with nothing to run");

    let run_out = run(false, &up, vec![], true, dir.path(), |context, out, docker| commands::host_up(context, out, docker, None));
    assert_eq!(run_out.outcome.unwrap_err().to_string(), commands::NOT_SIGNED_IN);
}

#[test]
fn status_and_down_read_the_record_and_purge_deletes_it() {
    let dir = TempDir::new("host-status-down");
    let docker = FakeDocker::new(true);
    let run_before = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_status(context, out, docker));
    run_before.outcome.unwrap();
    assert!(run_before.output.contains("not a Svartal machine"), "{}", run_before.output);

    host::write_record(
        &dir.path().join("config"),
        &host::HostRecord { machine_id: MACHINE_ID.into(), machine_name: "laptop".into(), image: "img".into() },
    )
    .unwrap();
    *docker.running.lock().unwrap() = Some(true);
    let run_status = run(true, &docker, vec!["ready"], true, dir.path(), |context, out, docker| commands::host_status(context, out, docker));
    run_status.outcome.unwrap();
    assert!(run_status.output.contains("container svartal-host is running"), "{}", run_status.output);
    assert!(run_status.output.contains("Your workspace is ready."), "{}", run_status.output);
    assert!(run_status.output.contains("environment-1234"), "{}", run_status.output);

    let run_down = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_down(context, out, docker, false));
    run_down.outcome.unwrap();
    assert!(run_down.output.contains("removed"), "{}", run_down.output);
    assert!(host::read_record(&dir.path().join("config")).is_some(), "a plain down forgot the machine");

    let run_purge = run(true, &docker, vec![], true, dir.path(), |context, out, docker| commands::host_down(context, out, docker, true));
    run_purge.outcome.unwrap();
    assert!(host::read_record(&dir.path().join("config")).is_none(), "purge kept the record");
    let calls = docker.calls();
    for volume in ["svartal-host-config", "svartal-host-state", "svartal-run"] {
        assert!(calls.iter().any(|call| call == &format!("volume rm -f {volume}")), "{calls:?}");
    }
}
