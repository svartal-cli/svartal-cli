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
pub const ENV_FILE: &str = "host.env";

// ---------------------------------------------------------------------------
// Instances.

/// Which machine on this computer a command is about.
///
/// One computer can host more than one Svartal machine — the reason is
/// testing what happens *between* machines without a second computer — and
/// two machines that share a container name, a volume, or the local record
/// would silently be one machine. So every name a machine owns is derived
/// here and nowhere else.
///
/// The instance nobody named keeps the names the first release wrote, byte
/// for byte, so a machine that is already running stays the same machine
/// after an upgrade.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instance {
    name: Option<String>,
}

/// Said back to a person who typed a name this cannot use.
pub const INSTANCE_NAME_RULE: &str = "An instance name is 1 to 32 characters long, starts with a lowercase letter or a digit, and holds only lowercase letters, digits and dashes.";

impl Instance {
    /// The machine a person who never typed `--instance` means.
    pub fn default_instance() -> Self {
        Self { name: None }
    }

    /// A `--instance` value, or `None` for the default machine. The shape is
    /// checked here rather than by docker, because a name docker refuses
    /// halfway through `up` would leave a machine record on the account with
    /// no container to answer for it.
    pub fn parse(name: Option<&str>) -> Result<Self, String> {
        let Some(name) = name.map(str::trim) else {
            return Ok(Self::default_instance());
        };
        let shape = name.len() <= 32
            && name.starts_with(|character: char| character.is_ascii_lowercase() || character.is_ascii_digit())
            && name.chars().all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-');
        if !shape {
            return Err(format!("`{name}` is not a name an instance can have. {INSTANCE_NAME_RULE}"));
        }
        Ok(Self { name: Some(name.to_string()) })
    }

    /// The instance a record file under the state directory belongs to, or
    /// `None` when the file is not one of ours.
    fn from_record_file(file_name: &str) -> Option<Self> {
        if file_name == RECORD_FILE {
            return Some(Self::default_instance());
        }
        let name = file_name.strip_prefix("host-")?.strip_suffix(".json")?;
        Self::parse(Some(name)).ok()
    }

    /// The name a person typed, or `None` for the default machine.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn derived(&self, default: &str, stem: &str, tail: &str) -> String {
        match &self.name {
            None => default.to_string(),
            Some(name) => format!("{stem}-{name}{tail}"),
        }
    }

    pub fn container(&self) -> String {
        self.derived(CONTAINER_NAME, CONTAINER_NAME, "")
    }

    pub fn config_volume(&self) -> String {
        self.derived(CONFIG_VOLUME, CONTAINER_NAME, "-config")
    }

    pub fn state_volume(&self) -> String {
        self.derived(STATE_VOLUME, CONTAINER_NAME, "-state")
    }

    pub fn run_volume(&self) -> String {
        self.derived(RUN_VOLUME, RUN_VOLUME, "")
    }

    pub fn record_file(&self) -> String {
        self.derived(RECORD_FILE, "host", ".json")
    }

    pub fn env_file(&self) -> String {
        self.derived(ENV_FILE, "host", ".env")
    }
}

/// Every machine this computer knows about, default first: one per record
/// file `up` has written. This is what `sv host status` without `--instance`
/// walks, so a machine started with `--instance` is never lost by forgetting
/// the word it was started with.
pub fn known_instances(state_directory: &Path) -> Vec<Instance> {
    let Ok(entries) = std::fs::read_dir(state_directory) else {
        return Vec::new();
    };
    let mut instances: Vec<Instance> = entries
        .flatten()
        .filter_map(|entry| Instance::from_record_file(entry.file_name().to_str()?))
        .collect();
    instances.sort();
    instances.dedup();
    instances
}

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

/// Whether this instance's host container exists, and whether it is running.
pub fn container_state(docker: &dyn Docker, instance: &Instance) -> Result<Option<bool>, String> {
    let output = docker.run(&args(&["inspect", "--format", "{{.State.Running}}", &instance.container()]), None)?;
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
    #[serde(default)]
    pub component: Option<String>,
}

/// What Svartal knows about this machine's own software: the version the
/// host reported, the newest one in the catalogue, and whether the host is
/// the kind that fetches its own updates. `None` from a server that predates
/// host self-update, or for a machine that is not a host.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostUpdate {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub image_ref: Option<String>,
    /// When the host last asked Svartal for updates; `None` when it never has.
    #[serde(default)]
    pub deployments_pulled_at: Option<String>,
    #[serde(default)]
    pub up_to_date: bool,
    #[serde(default)]
    pub update_available: bool,
    #[serde(default)]
    pub self_updating: bool,
    /// Written by the server when the machine is online but its host never
    /// asks — host software older than self-update.
    #[serde(default)]
    pub blocked_reason: Option<String>,
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
    /// The newest host image in the catalogue — the machine's own software,
    /// as opposed to `release`, which is the workspace image.
    #[serde(default)]
    pub host_release: Option<HostRelease>,
    #[serde(default)]
    pub host_update: Option<HostUpdate>,
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
    // The name rides along even when the machine is known: it is how
    // `sv host up --name` renames a machine that was first registered with
    // this computer's hostname.
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

pub fn read_record(state_directory: &Path, instance: &Instance) -> Option<HostRecord> {
    let bytes = crate::fsutil::read_private_file(&state_directory.join(instance.record_file()), 65_536).ok()??;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_record(state_directory: &Path, instance: &Instance, record: &HostRecord) -> Result<(), String> {
    crate::fsutil::ensure_state_directory(state_directory).map_err(|error| error.to_string())?;
    crate::fsutil::write_private_file(
        &state_directory.join(instance.record_file()),
        serde_json::to_string_pretty(record).unwrap_or_default().as_bytes(),
    )
    .map_err(|error| error.to_string())
}

pub fn remove_record(state_directory: &Path, instance: &Instance) {
    let _ = crate::fsutil::remove_file(&state_directory.join(instance.record_file()));
}

// ---------------------------------------------------------------------------
// The run.

/// Everything the host container is started with.
pub struct HostPlan<'a> {
    pub instance: &'a Instance,
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
    // The machine mounts its own volumes into the containers it creates —
    // the runners' credential homes out of the state volume, the broker
    // socket out of the run volume — and it can only name them if it is told
    // which ones are its. A second machine handed the first one's names
    // would quietly share both.
    let mut body = format!(
        "SVARTAL_MACHINE_ID={}\nSVARTAL_ENROLLMENT_TOKEN={}\nSVARTAL_MANAGED_IMAGE_REF={}\nSVARTAL_BROKER_API_BASE_URL={}\nT3CODE_RELAY_URL={}\nT3CODE_CLOUD_ISSUER={}\nSVARTAL_STATE_VOLUME={}\nSVARTAL_RUN_VOLUME={}\n",
        plan.machine_id,
        plan.enrollment_token,
        plan.managed_image_ref,
        plan.api_base_url,
        plan.relay_url,
        plan.issuer,
        plan.instance.state_volume(),
        plan.instance.run_volume(),
    );
    if plan.registry_auth {
        body.push_str("SVARTAL_REGISTRY_AUTH_REQUIRED=true\nSVARTAL_REGISTRY_HOST=ghcr.io\nDOCKER_CONFIG=/etc/svartal/docker\n");
    }
    body
}

/// The `docker run` for the host container. Pure, so a test can pin it.
pub fn run_args(instance: &Instance, image: &str, env_file: &Path) -> Vec<String> {
    args(&[
        "run",
        "-d",
        "--name",
        &instance.container(),
        "--restart",
        "unless-stopped",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "-v",
        &format!("{}:/etc/svartal", instance.config_volume()),
        "-v",
        &format!("{}:/var/lib/svartal", instance.state_volume()),
        "-v",
        &format!("{}:/run/svartal", instance.run_volume()),
        "--env-file",
        &env_file.to_string_lossy(),
        image,
    ])
}

/// Copy the registry credential into the config volume, through stdin, using
/// the host image itself as the helper (it is alpine, and already pulled).
pub fn install_registry_auth(docker: &dyn Docker, instance: &Instance, image: &str, auth: &str) -> Result<(), String> {
    let output = docker.run(
        &args(&[
            "run",
            "--rm",
            "-i",
            "--entrypoint",
            "sh",
            "-v",
            &format!("{}:/etc/svartal", instance.config_volume()),
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
pub fn recent_logs(docker: &dyn Docker, instance: &Instance) -> String {
    docker
        .run(&args(&["logs", "--tail", "12", &instance.container()]), None)
        .map(|output| {
            let mut text = output.stdout;
            if !output.stderr.is_empty() {
                text.push_str(&output.stderr);
            }
            text.trim().to_string()
        })
        .unwrap_or_default()
}

/// The image this instance's host container is actually running: what
/// `docker run` was given, the digest that tag resolved to, and the version
/// label the image carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningImage {
    pub image: String,
    pub digest_ref: Option<String>,
    pub version: Option<String>,
}

/// A value docker printed for a field the image does not have.
fn docker_value(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() || text == "<no value>" { None } else { Some(text.to_string()) }
}

/// What the host container is running right now, straight from the engine.
///
/// A machine that updates itself is on whatever image it last pulled, which
/// is not necessarily the one `sv host up` started it with, so this asks the
/// container rather than the local record. `None` when it is not running.
pub fn running_host_image(docker: &dyn Docker, instance: &Instance) -> Option<RunningImage> {
    if container_state(docker, instance).ok().flatten() != Some(true) {
        return None;
    }
    let inspected = docker.run(&args(&["inspect", "--format", "{{.Config.Image}}", &instance.container()]), None).ok()?;
    if !inspected.success {
        return None;
    }
    let image = docker_value(&inspected.stdout)?;
    let mut running = RunningImage { image: image.clone(), digest_ref: None, version: None };
    let details = docker.run(
        &args(&[
            "image",
            "inspect",
            "--format",
            "{{index .RepoDigests 0}}|{{index .Config.Labels \"org.opencontainers.image.version\"}}",
            &image,
        ]),
        None,
    );
    if let Ok(details) = details
        && details.success
    {
        let text = details.stdout.trim();
        let (digest, version) = text.split_once('|').unwrap_or((text, ""));
        running.digest_ref = docker_value(digest);
        running.version = docker_value(version);
    }
    Some(running)
}

/// What `sv host status` says about the machine's own software: which host
/// image it is on, and whether Svartal has a newer one it will take by
/// itself. Pure, so every branch is a test rather than a container.
pub fn host_software_sentences(
    running: Option<&RunningImage>,
    update: Option<&HostUpdate>,
    host_release: Option<&HostRelease>,
) -> Vec<String> {
    let mut sentences = Vec::new();
    match running {
        Some(image) => {
            let version = image.version.as_deref().unwrap_or("unknown version");
            let reference = image.digest_ref.as_deref().unwrap_or(image.image.as_str());
            sentences.push(format!("Host software {version} ({reference})."));
        }
        None => sentences.push("Host software: the container is not running.".to_string()),
    }
    // No update block at all is an older server, or a machine that is not a
    // host: nothing truthful can be said about its updates, so nothing is.
    let Some(update) = update else {
        return sentences;
    };
    let current = host_release.and_then(|release| release.version.as_deref()).unwrap_or("unknown");
    if let Some(reason) = update.blocked_reason.as_deref().map(str::trim).filter(|reason| !reason.is_empty()) {
        sentences.push(reason.to_string());
    } else if update.self_updating && update.up_to_date {
        sentences.push(format!("The current host release is {current}; this machine is on it and updates itself."));
    } else if update.self_updating && update.update_available {
        sentences.push(format!("The current host release is {current}; this machine is behind and will take it at its next check."));
    } else if !update.self_updating {
        sentences.push("This machine has not asked Svartal for updates yet. Run `sv host up` to refresh its software.".to_string());
    }
    sentences
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

/// A machine name the API accepts: printable, no control characters, at most
/// 64 characters. A person's own `--name` goes through this too, so a name
/// this CLI would refuse never reaches Svartal.
pub fn sanitize_machine_name(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(64)
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() { "my-computer".to_string() } else { cleaned }
}

/// The name a machine record gets when nobody passed one: this computer's
/// hostname, without the `.local` suffix, or a plain word when it has none.
///
/// A work laptop's hostname is often its serial number, which is a poor name
/// to see in `sv envs` — hence `sv host up --name`.
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

/// The machine name an `up` with no `--name` uses.
///
/// A second machine on the same computer carries its instance in the name:
/// the two records are told apart by their ids, but a person reading
/// `sv envs` sees names, and two rows called `Marcs-MacBook` are two rows
/// nobody can choose between.
pub fn machine_name_for(instance: &Instance, hostname: Option<&str>) -> String {
    let base = machine_name(hostname);
    match instance.name() {
        None => base,
        Some(name) => {
            let room = 64usize.saturating_sub(name.len() + 1);
            let base: String = base.chars().take(room).collect();
            format!("{}-{name}", base.trim_end_matches('-'))
        }
    }
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
        let run = run_args(&Instance::default_instance(), "ghcr.io/x/svartal-host:latest", Path::new("/tmp/host.env"));
        assert_eq!(run[0..4], ["run", "-d", "--name", "svartal-host"]);
        assert!(run.contains(&"/var/run/docker.sock:/var/run/docker.sock".to_string()));
        assert!(run.contains(&"svartal-host-config:/etc/svartal".to_string()));
        assert!(run.contains(&"svartal-host-state:/var/lib/svartal".to_string()));
        assert!(run.contains(&"svartal-run:/run/svartal".to_string()));
        assert!(run.iter().all(|argument| !argument.starts_with("-e")));
        assert_eq!(run.last().map(String::as_str), Some("ghcr.io/x/svartal-host:latest"));
    }

    #[test]
    fn the_default_instance_keeps_the_names_the_first_release_wrote() {
        let default = Instance::default_instance();
        assert_eq!(default.container(), CONTAINER_NAME);
        assert_eq!(default.config_volume(), CONFIG_VOLUME);
        assert_eq!(default.state_volume(), STATE_VOLUME);
        assert_eq!(default.run_volume(), RUN_VOLUME);
        assert_eq!(default.record_file(), RECORD_FILE);
        assert_eq!(default.env_file(), ENV_FILE);
        assert_eq!(Instance::parse(None), Ok(default));

        let named = Instance::parse(Some("m3b")).unwrap();
        assert_eq!(named.container(), "svartal-host-m3b");
        assert_eq!(named.config_volume(), "svartal-host-m3b-config");
        assert_eq!(named.state_volume(), "svartal-host-m3b-state");
        assert_eq!(named.run_volume(), "svartal-run-m3b");
        assert_eq!(named.record_file(), "host-m3b.json");
        assert_eq!(named.env_file(), "host-m3b.env");
    }

    #[test]
    fn an_instance_name_is_a_lowercase_word_and_nothing_else() {
        assert!(Instance::parse(Some("m3b")).is_ok());
        assert!(Instance::parse(Some("a")).is_ok());
        assert!(Instance::parse(Some("second-mac-9")).is_ok());
        assert!(Instance::parse(Some(&"x".repeat(32))).is_ok());
        for refused in ["", "-b", "M3B", "my instance", "b_2", "b.2", "über", &"x".repeat(33)] {
            let error = Instance::parse(Some(refused)).unwrap_err();
            assert!(error.contains(INSTANCE_NAME_RULE), "{error}");
        }
    }

    #[test]
    fn every_record_file_in_the_state_directory_is_an_instance() {
        let directory = std::env::temp_dir().join(format!("sv-host-instances-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        for file in ["host.json", "host-m3b.json", "host-a.json", "host.env", "host-m3b.env", "shortnames.json", "host-Bad.json"] {
            std::fs::write(directory.join(file), "{}").unwrap();
        }
        let found: Vec<Option<String>> =
            known_instances(&directory).iter().map(|instance| instance.name().map(str::to_string)).collect();
        assert_eq!(found, vec![None, Some("a".to_string()), Some("m3b".to_string())]);
        assert!(known_instances(&directory.join("missing")).is_empty());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn the_env_file_carries_the_token_and_the_registry_switch() {
        let plan = HostPlan {
            instance: &Instance::default_instance(),
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
        assert!(body.contains("SVARTAL_STATE_VOLUME=svartal-host-state\n"));
        assert!(body.contains("SVARTAL_RUN_VOLUME=svartal-run\n"));
        let named = Instance::parse(Some("m3b")).unwrap();
        let named_body = env_file_body(&HostPlan { instance: &named, ..plan });
        assert!(named_body.contains("SVARTAL_STATE_VOLUME=svartal-host-m3b-state\n"), "{named_body}");
        assert!(named_body.contains("SVARTAL_RUN_VOLUME=svartal-run-m3b\n"), "{named_body}");
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
    fn a_second_machine_on_this_computer_is_named_after_its_instance() {
        let default = Instance::default_instance();
        let named = Instance::parse(Some("m3b")).unwrap();
        assert_eq!(machine_name_for(&default, Some("Marcs-MacBook.local")), "Marcs-MacBook");
        assert_eq!(machine_name_for(&named, Some("Marcs-MacBook.local")), "Marcs-MacBook-m3b");
        assert_eq!(machine_name_for(&named, Some(&"x".repeat(100))).len(), 64);
    }

    #[test]
    fn a_persons_own_name_keeps_its_spaces_and_loses_its_junk() {
        assert_eq!(sanitize_machine_name("  work laptop  "), "work laptop");
        assert_eq!(sanitize_machine_name("work\nlaptop"), "worklaptop");
        assert_eq!(sanitize_machine_name("   "), "my-computer");
        assert_eq!(sanitize_machine_name(&"x".repeat(100)).len(), 64);
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

    fn update(blocked: Option<&str>, self_updating: bool, up_to_date: bool, update_available: bool) -> HostUpdate {
        HostUpdate {
            version: Some("0.1.98".into()),
            image_ref: None,
            deployments_pulled_at: None,
            up_to_date,
            update_available,
            self_updating,
            blocked_reason: blocked.map(str::to_string),
        }
    }

    fn release(version: &str) -> HostRelease {
        HostRelease { image_ref: "ghcr.io/x/svartal-host:latest".into(), version: Some(version.into()), component: Some("host".into()) }
    }

    #[test]
    fn the_host_software_lines_say_what_is_running_and_what_is_current() {
        let running = RunningImage {
            image: "ghcr.io/x/svartal-host:latest".into(),
            digest_ref: Some("ghcr.io/x/svartal-host@sha256:abc".into()),
            version: Some("0.1.98".into()),
        };
        let current = release("0.1.99");

        // Up to date, and it keeps itself that way.
        let lines = host_software_sentences(Some(&running), Some(&update(None, true, true, false)), Some(&current));
        assert_eq!(lines[0], "Host software 0.1.98 (ghcr.io/x/svartal-host@sha256:abc).");
        assert_eq!(lines[1], "The current host release is 0.1.99; this machine is on it and updates itself.");

        // Behind, but it will take the new one on its own.
        let lines = host_software_sentences(Some(&running), Some(&update(None, true, false, true)), Some(&current));
        assert_eq!(lines[1], "The current host release is 0.1.99; this machine is behind and will take it at its next check.");

        // Never asked: the person has to refresh it by hand.
        let lines = host_software_sentences(Some(&running), Some(&update(None, false, false, true)), Some(&current));
        assert_eq!(lines[1], "This machine has not asked Svartal for updates yet. Run `sv host up` to refresh its software.");

        // The server's own sentence wins over every guess this could make.
        let blocked = update(Some("This machine's host software predates self-update."), false, false, true);
        let lines = host_software_sentences(Some(&running), Some(&blocked), Some(&current));
        assert_eq!(lines[1], "This machine's host software predates self-update.");

        // An older server says nothing about updates, so neither does this.
        let lines = host_software_sentences(Some(&running), None, Some(&current));
        assert_eq!(lines, vec!["Host software 0.1.98 (ghcr.io/x/svartal-host@sha256:abc).".to_string()]);
    }

    #[test]
    fn an_unlabelled_image_and_a_stopped_container_still_have_a_line() {
        let bare = RunningImage { image: "svartal-host:dev".into(), digest_ref: None, version: None };
        let lines = host_software_sentences(Some(&bare), None, None);
        assert_eq!(lines, vec!["Host software unknown version (svartal-host:dev).".to_string()]);

        let lines = host_software_sentences(None, Some(&update(None, true, true, false)), None);
        assert_eq!(lines[0], "Host software: the container is not running.");
        assert_eq!(lines[1], "The current host release is unknown; this machine is on it and updates itself.");
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
