//! `sv host up|status|down`: this computer as a Svartal machine.
//!
//! The machine side of Svartal runs as one container (brok's
//! `docs/host-mode.md`): a broker, a workspace reconciler, and one workspace
//! container per person the owner grants access to. Everything a person had
//! to do by hand — create the machine record, mint an enrollment token, find
//! the current workspace image, write the `docker run` with its four mounts,
//! grant themselves access, wait for the workspace — is one client API call
//! plus one `docker run`, and this module is that.
//!
//! What is deliberately *not* here: any secret on a command line. The
//! enrollment token travels in a private `--env-file` the docker client
//! reads, never in argv; the registry credential is copied into the config
//! volume through stdin.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::api::ApiError;
use crate::http::{HttpTransport, Request};

/// The image `brok host serve` ships in. Published by brok's host-image
/// workflow on every push to its main branch.
pub const DEFAULT_HOST_IMAGE: &str = "ghcr.io/svartal-cli/svartal-host:latest";
pub const HOST_IMAGE_ENV: &str = "SVARTAL_HOST_IMAGE";
pub const DOCKER_BINARY_ENV: &str = "SVARTAL_DOCKER_BINARY";
pub const CONTAINER_NAME: &str = "svartal-host";
pub const CONFIG_VOLUME: &str = "svartal-host-config";
pub const STATE_VOLUME: &str = "svartal-host-state";
pub const RUN_VOLUME: &str = "svartal-run";
/// The file under the state directory that remembers which machine record
/// this computer is, so `up` reuses it and `status`/`down` find it.
pub const RECORD_FILE: &str = "host.json";

// ---------------------------------------------------------------------------
// Docker.

#[derive(Debug, Clone)]
pub struct DockerOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// The docker client, behind a trait so the command's decisions are testable
/// without an engine. `stdin` is for the one call that hands over a secret.
pub trait Docker: Sync {
    fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<DockerOutput, String>;
}

pub struct ProcessDocker;

impl Docker for ProcessDocker {
    fn run(&self, args: &[String], stdin: Option<&[u8]>) -> Result<DockerOutput, String> {
        use std::io::Write as _;
        use std::process::{Command, Stdio};
        let binary = std::env::var(DOCKER_BINARY_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "docker".to_string());
        let mut command = Command::new(&binary);
        command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        command.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = command.spawn().map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                "Docker is not installed on this computer, or `docker` is not on PATH. Install Docker Desktop (or OrbStack, or the docker engine) and run `sv host up` again.".to_string()
            } else {
                format!("Could not run docker: {error}")
            }
        })?;
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            let _ = pipe.write_all(bytes);
        }
        let output = child.wait_with_output().map_err(|error| format!("Could not run docker: {error}"))?;
        Ok(DockerOutput {
            success: output.status.success(),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }
}

fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|part| (*part).to_string()).collect()
}

/// `docker info`: is there an engine to talk to.
pub fn engine_ready(docker: &dyn Docker) -> Result<(), String> {
    let output = docker.run(&args(&["info", "--format", "{{.ServerVersion}}"]), None)?;
    if output.success && !output.stdout.trim().is_empty() {
        return Ok(());
    }
    Err("Docker is not running on this computer. Start Docker Desktop (or OrbStack, or the docker engine) and run `sv host up` again.".to_string())
}

/// Whether the host container exists, and whether it is running.
pub fn container_state(docker: &dyn Docker) -> Result<Option<bool>, String> {
    let output = docker.run(&args(&["inspect", "--format", "{{.State.Running}}", CONTAINER_NAME]), None)?;
    if !output.success {
        return Ok(None);
    }
    Ok(Some(output.stdout.trim() == "true"))
}

// ---------------------------------------------------------------------------
// The registry credential.

/// A `ghcr.io` credential from the docker client's own configuration: the
/// `auths` entry, or the credential helper (`credsStore` / `credHelpers`)
/// Docker Desktop keeps it in. `None` when the person never logged in.
pub fn ghcr_auth_from_docker_config(home: &Path, docker_config_env: Option<&str>) -> Option<String> {
    let directory = docker_config_env
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".docker"));
    let config: Value = serde_json::from_str(&std::fs::read_to_string(directory.join("config.json")).ok()?).ok()?;
    if let Some(auth) = config.pointer("/auths/ghcr.io/auth").and_then(Value::as_str)
        && !auth.is_empty()
    {
        return Some(auth.to_string());
    }
    let helper = config
        .pointer("/credHelpers/ghcr.io")
        .and_then(Value::as_str)
        .or_else(|| config.get("credsStore").and_then(Value::as_str))?;
    credential_helper_auth(helper)
}

fn credential_helper_auth(helper: &str) -> Option<String> {
    use base64::Engine as _;
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    if helper.is_empty() || !helper.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
        return None;
    }
    let mut child = Command::new(format!("docker-credential-{helper}"))
        .arg("get")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(b"https://ghcr.io\n").ok()?;
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let parsed: Value = serde_json::from_slice(&output.stdout).ok()?;
    let username = parsed.get("Username").and_then(Value::as_str)?;
    let secret = parsed.get("Secret").and_then(Value::as_str)?;
    if username.is_empty() || secret.is_empty() {
        return None;
    }
    Some(base64::engine::general_purpose::STANDARD.encode(format!("{username}:{secret}")))
}

/// The docker config the reconciler pulls the workspace image with.
pub fn registry_config_json(auth: &str) -> String {
    json!({ "auths": { "ghcr.io": { "auth": auth } } }).to_string()
}

// ---------------------------------------------------------------------------
// The machine record, as the API hands it back.

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRelease {
    pub image_ref: String,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostIntent {
    pub lifecycle_state: String,
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub last_error: Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostMachine {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRegistration {
    pub machine: HostMachine,
    #[serde(default)]
    pub enrollment_token: Option<String>,
    #[serde(default)]
    pub workspace_intent: Option<HostIntent>,
    #[serde(default)]
    pub release: Option<HostRelease>,
}

fn parse_registration(body: Value, action: &str) -> Result<HostRegistration, ApiError> {
    let data = body.get("data").cloned().unwrap_or(Value::Null);
    serde_json::from_value(data)
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })
}

fn send_json(
    http: &dyn HttpTransport,
    request: Request,
    access_token: &str,
    action: &str,
) -> Result<Value, ApiError> {
    let response = http
        .send(
            request
                .header("authorization", &format!("Bearer {access_token}"))
                .header("accept", "application/json"),
        )
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })?;
    if response.status == 401 || response.status == 403 {
        return Err(ApiError::Unauthorized { action: action.to_string() });
    }
    if !response.is_success() {
        return Err(ApiError::Failed {
            action: action.to_string(),
            detail: format!("Svartal returned HTTP {}.", response.status),
        });
    }
    response
        .json()
        .map_err(|error| ApiError::Failed { action: action.to_string(), detail: error.to_string() })
}

/// `POST /api/v1/client/host-machines`: create (or reuse) this computer's
/// machine record, mint a fresh enrollment token, grant the caller a
/// workspace, and learn the current workspace image — one call.
pub fn register_host(
    http: &dyn HttpTransport,
    api_base_url: &str,
    access_token: &str,
    name: &str,
    machine_id: Option<&str>,
) -> Result<HostRegistration, ApiError> {
    let action = "register this computer as a machine";
    let mut body = json!({ "name": name });
    if let Some(id) = machine_id {
        body["machine_id"] = json!(id);
    }
    let response = send_json(
        http,
        Request::post(format!("{api_base_url}/api/v1/client/host-machines")).json(body),
        access_token,
        action,
    )?;
    parse_registration(response, action)
}

/// `GET /api/v1/client/host-machines/:id`: the machine and the caller's
/// workspace on it.
pub fn host_status(
    http: &dyn HttpTransport,
    api_base_url: &str,
    access_token: &str,
    machine_id: &str,
) -> Result<HostRegistration, ApiError> {
    let action = "read this computer's machine record";
    let response = send_json(
        http,
        Request::get(format!("{api_base_url}/api/v1/client/host-machines/{machine_id}")),
        access_token,
        action,
    )?;
    parse_registration(response, action)
}

// ---------------------------------------------------------------------------
// What this computer remembers.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HostRecord {
    pub machine_id: String,
    pub machine_name: String,
    pub image: String,
}

pub fn read_record(state_directory: &Path) -> Option<HostRecord> {
    let bytes = crate::fsutil::read_private_file(&state_directory.join(RECORD_FILE), 65_536).ok()??;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_record(state_directory: &Path, record: &HostRecord) -> Result<(), String> {
    crate::fsutil::ensure_state_directory(state_directory).map_err(|error| error.to_string())?;
    crate::fsutil::write_private_file(
        &state_directory.join(RECORD_FILE),
        serde_json::to_string_pretty(record).unwrap_or_default().as_bytes(),
    )
    .map_err(|error| error.to_string())
}

pub fn remove_record(state_directory: &Path) {
    let _ = crate::fsutil::remove_file(&state_directory.join(RECORD_FILE));
}

// ---------------------------------------------------------------------------
// The run.

/// Everything the host container is started with.
pub struct HostPlan<'a> {
    pub image: &'a str,
    pub machine_id: &'a str,
    pub enrollment_token: &'a str,
    pub managed_image_ref: &'a str,
    pub api_base_url: &'a str,
    pub relay_url: &'a str,
    pub issuer: &'a str,
    pub registry_auth: bool,
}

/// The private environment file the docker client reads: the one place the
/// enrollment token is written, and it is deleted the moment the container
/// has started.
pub fn env_file_body(plan: &HostPlan<'_>) -> String {
    let mut body = format!(
        "SVARTAL_MACHINE_ID={}\nSVARTAL_ENROLLMENT_TOKEN={}\nSVARTAL_MANAGED_IMAGE_REF={}\nSVARTAL_BROKER_API_BASE_URL={}\nT3CODE_RELAY_URL={}\nT3CODE_CLOUD_ISSUER={}\n",
        plan.machine_id, plan.enrollment_token, plan.managed_image_ref, plan.api_base_url, plan.relay_url, plan.issuer,
    );
    if plan.registry_auth {
        body.push_str("SVARTAL_REGISTRY_AUTH_REQUIRED=true\nSVARTAL_REGISTRY_HOST=ghcr.io\nDOCKER_CONFIG=/etc/svartal/docker\n");
    }
    body
}

/// The `docker run` for the host container. Pure, so a test can pin it.
pub fn run_args(image: &str, env_file: &Path) -> Vec<String> {
    args(&[
        "run",
        "-d",
        "--name",
        CONTAINER_NAME,
        "--restart",
        "unless-stopped",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        &format!("{CONFIG_VOLUME}:/etc/svartal"),
        "-v",
        &format!("{STATE_VOLUME}:/var/lib/svartal"),
        "-v",
        &format!("{RUN_VOLUME}:/run/svartal"),
        "--env-file",
        &env_file.to_string_lossy(),
        image,
    ])
}

/// Copy the registry credential into the config volume, through stdin, using
/// the host image itself as the helper (it is alpine, and already pulled).
pub fn install_registry_auth(docker: &dyn Docker, image: &str, auth: &str) -> Result<(), String> {
    let output = docker.run(
        &args(&[
            "run",
            "--rm",
            "-i",
            "--entrypoint",
            "sh",
            "-v",
            &format!("{CONFIG_VOLUME}:/etc/svartal"),
            image,
            "-c",
            "umask 077 && mkdir -p /etc/svartal/docker && cat >/etc/svartal/docker/config.json",
        ]),
        Some(registry_config_json(auth).as_bytes()),
    )?;
    if output.success {
        Ok(())
    } else {
        Err(format!("Could not store the registry credential for the machine: {}", output.stderr))
    }
}

/// The last lines of the host container's log, for a failure message.
pub fn recent_logs(docker: &dyn Docker) -> String {
    docker
        .run(&args(&["logs", "--tail", "12", CONTAINER_NAME]), None)
        .map(|output| {
            let mut text = output.stdout;
            if !output.stderr.is_empty() {
                text.push_str(&output.stderr);
            }
            text.trim().to_string()
        })
        .unwrap_or_default()
}

/// The sentence for one workspace state, while `up` waits.
pub fn intent_sentence(intent: Option<&HostIntent>) -> String {
    match intent.map(|intent| intent.lifecycle_state.as_str()) {
        None | Some("requested") => "Waiting for the machine to pick up your workspace…".to_string(),
        Some("provisioning") => "Creating your workspace container…".to_string(),
        Some("ready") => "Your workspace is ready.".to_string(),
        Some("failed") => {
            let code = intent
                .and_then(|intent| intent.last_error.get("code"))
                .and_then(Value::as_str)
                .unwrap_or("host_reconcile_failed");
            format!("The machine could not create your workspace ({code}).")
        }
        Some(other) => format!("Workspace state: {other}."),
    }
}

/// The name a machine record gets: this computer's hostname, trimmed to what
/// the API accepts, or a plain word when it has none.
pub fn machine_name(hostname: Option<&str>) -> String {
    let name: String = hostname
        .unwrap_or("")
        .trim()
        .trim_end_matches(".local")
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
        .take(64)
        .collect();
    if name.is_empty() { "my-computer".to_string() } else { name }
}

pub fn local_hostname() -> Option<String> {
    let mut buffer = [0u8; 256];
    // SAFETY: gethostname writes at most len bytes into the buffer.
    let outcome = unsafe { libc_gethostname(buffer.as_mut_ptr(), buffer.len()) };
    if outcome != 0 {
        return None;
    }
    let end = buffer.iter().position(|byte| *byte == 0).unwrap_or(buffer.len());
    String::from_utf8(buffer[..end].to_vec()).ok().filter(|name| !name.is_empty())
}

unsafe extern "C" {
    #[link_name = "gethostname"]
    fn libc_gethostname(name: *mut u8, len: usize) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_run_has_the_four_mounts_and_no_secret_in_argv() {
        let run = run_args("ghcr.io/x/svartal-host:latest", Path::new("/tmp/host.env"));
        assert_eq!(run[0..4], ["run", "-d", "--name", "svartal-host"]);
        assert!(run.contains(&"/var/run/docker.sock:/var/run/docker.sock".to_string()));
        assert!(run.contains(&"svartal-host-config:/etc/svartal".to_string()));
        assert!(run.contains(&"svartal-host-state:/var/lib/svartal".to_string()));
        assert!(run.contains(&"svartal-run:/run/svartal".to_string()));
        assert!(run.iter().all(|argument| !argument.starts_with("-e")));
        assert_eq!(run.last().map(String::as_str), Some("ghcr.io/x/svartal-host:latest"));
    }

    #[test]
    fn the_env_file_carries_the_token_and_the_registry_switch() {
        let plan = HostPlan {
            image: "img",
            machine_id: "m-1",
            enrollment_token: "svartal-enroll-secret",
            managed_image_ref: "ghcr.io/x/k3@sha256:abc",
            api_base_url: "https://api.example",
            relay_url: "https://relay.example",
            issuer: "https://api.example",
            registry_auth: true,
        };
        let body = env_file_body(&plan);
        assert!(body.contains("SVARTAL_ENROLLMENT_TOKEN=svartal-enroll-secret\n"));
        assert!(body.contains("SVARTAL_MANAGED_IMAGE_REF=ghcr.io/x/k3@sha256:abc\n"));
        assert!(body.contains("DOCKER_CONFIG=/etc/svartal/docker\n"));
        let plan = HostPlan { registry_auth: false, ..plan };
        assert!(!env_file_body(&plan).contains("DOCKER_CONFIG"));
    }

    #[test]
    fn machine_names_are_hostnames_made_safe() {
        assert_eq!(machine_name(Some("Marcs-MacBook.local")), "Marcs-MacBook");
        assert_eq!(machine_name(Some("  ")), "my-computer");
        assert_eq!(machine_name(None), "my-computer");
        assert_eq!(machine_name(Some("bad name!")), "badname");
    }

    #[test]
    fn a_plain_auths_entry_is_used_and_a_missing_one_is_none() {
        let home = std::env::temp_dir().join(format!("sv-host-docker-{}", std::process::id()));
        std::fs::create_dir_all(home.join(".docker")).unwrap();
        std::fs::write(home.join(".docker/config.json"), r#"{"auths":{"ghcr.io":{"auth":"dXNlcjp0b2tlbg=="}}}"#).unwrap();
        assert_eq!(ghcr_auth_from_docker_config(&home, None), Some("dXNlcjp0b2tlbg==".to_string()));
        std::fs::write(home.join(".docker/config.json"), r#"{"auths":{}}"#).unwrap();
        assert_eq!(ghcr_auth_from_docker_config(&home, None), None);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn workspace_states_have_sentences() {
        assert!(intent_sentence(None).starts_with("Waiting"));
        let failed = HostIntent {
            lifecycle_state: "failed".into(),
            environment_id: None,
            last_error: json!({ "code": "host_capacity_memory" }),
        };
        assert_eq!(intent_sentence(Some(&failed)), "The machine could not create your workspace (host_capacity_memory).");
    }
}
