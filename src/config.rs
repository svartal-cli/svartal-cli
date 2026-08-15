//! Where Svartal is, who this client is, and where the credential lives.
//!
//! Port of `src/config.ts` in the TypeScript CLI, plus the two library
//! functions it leans on: `isAllowedWebOidcRedirectUri`
//! (`@svartal/client/identity`) and `normalizeSecureRelayUrl`
//! (`@t3tools/shared/relayUrl`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use url::Url;

/// `DEFAULT_WEB_OIDC_ISSUER`.
pub const DEFAULT_ISSUER: &str = "https://api.svartal.com";
/// `DEFAULT_WEB_OIDC_AUDIENCE`. `ID-3`: this is what makes an access token
/// usable against the relay.
pub const DEFAULT_AUDIENCE: &str = "t3-code-relay";
/// `DEFAULT_RELAY_URL`.
pub const DEFAULT_RELAY_URL: &str = "https://relay.svartal.com";

/// `ID-1`: the terminal is its own registered client, so a terminal grant can
/// be revoked on its own. `t3-web`, `t3-desktop` and `t3-mobile` are Ivaldi's.
pub const CLIENT_ID: &str = "svartal-cli";

/// `ID-4`: `openid` is required, and `offline_access` is not optional here —
/// without a refresh token the CLI would open a browser on every command.
pub const SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

/// `ID-6`/`ID-7`: the only two loopback callbacks Svartal accepts, in
/// preference order. A third port would be refused by the provider, so this
/// list is not a free choice. Two entries mean a second `sva login` can
/// still run while the first port is held.
pub const REDIRECT_URIS: [&str; 2] =
    ["http://127.0.0.1:5733/auth/callback", "http://127.0.0.1:5734/auth/callback"];

#[derive(Debug)]
pub struct ConfigError(pub String);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackRedirect {
    pub redirect_uri: String,
    pub host: String,
    pub port: u16,
    pub pathname: String,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub issuer: String,
    pub audience: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub redirects: Vec<LoopbackRedirect>,
    /// Relay origin. Environment links and per-environment state live here.
    pub relay_url: String,
    /// Svartal API origin. Machines and workspaces live here.
    pub api_base_url: String,
    /// Directory holding the token file and the DPoP key.
    pub state_directory: PathBuf,
}

/// The environment as a plain map, so a test can build one without touching
/// the process.
pub type Environment = BTreeMap<String, String>;

pub fn environment_from_process() -> Environment {
    std::env::vars().collect()
}

fn trimmed(environment: &Environment, name: &str) -> String {
    environment.get(name).map(|value| value.trim().to_string()).unwrap_or_default()
}

/// `normalizeHttpsOrigin`: an HTTPS URL with no credentials, query or
/// fragment, serialized as origin plus path with trailing slashes removed.
pub fn normalize_https_origin(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let origin = url.origin().ascii_serialization();
    let path = url.path().trim_end_matches('/');
    Some(format!("{origin}{path}"))
}

/// `normalizeSecureRelayUrl`: HTTPS, no credentials, no query, no fragment,
/// and a path that is nothing but slashes. The relay is an origin, never a
/// prefix.
pub fn normalize_secure_relay_url(value: &str) -> Option<String> {
    let url = Url::parse(value.trim()).ok()?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.path().chars().all(|character| character == '/')
        || url.path().is_empty()
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// `ID-6`: allowed if it parses, carries no credentials and no fragment, and
/// is either HTTPS (any host) or exactly one of the two registered loopback
/// callbacks. `ID-8`: the comparison is on the fully normalized URL, so
/// `localhost` is not `127.0.0.1`.
pub fn is_allowed_redirect_uri(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else { return false };
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    REDIRECT_URIS.contains(&url.as_str())
}

pub fn resolve_issuer(environment: &Environment) -> String {
    normalize_https_origin(&trimmed(environment, "SVARTAL_ISSUER"))
        .unwrap_or_else(|| DEFAULT_ISSUER.to_string())
}

pub fn resolve_audience(environment: &Environment) -> String {
    let value = trimmed(environment, "SVARTAL_AUDIENCE");
    if value.is_empty() { DEFAULT_AUDIENCE.to_string() } else { value }
}

pub fn resolve_relay_url(environment: &Environment) -> String {
    normalize_secure_relay_url(&trimmed(environment, "SVARTAL_RELAY_URL"))
        .unwrap_or_else(|| DEFAULT_RELAY_URL.to_string())
}

/// The Svartal API and the OIDC issuer are the same origin today. Resolving
/// the API base from the issuer keeps a self-hosted or staging issuer working
/// without a second variable; `SVARTAL_API_URL` is the escape hatch when they
/// are split.
pub fn resolve_api_base_url(environment: &Environment) -> String {
    normalize_https_origin(&trimmed(environment, "SVARTAL_API_URL"))
        .unwrap_or_else(|| resolve_issuer(environment))
}

/// XDG first, then `~/.config/svartal`, so the credential sits next to every
/// other CLI credential on the box and can be removed by deleting one
/// directory. This is the same path the npm CLI uses — deliberately: a person
/// signed in with one CLI is signed in with the other.
pub fn resolve_state_directory(environment: &Environment) -> Result<PathBuf, ConfigError> {
    let explicit = trimmed(environment, "SVARTAL_CONFIG_DIR");
    if !explicit.is_empty() {
        return Ok(PathBuf::from(explicit));
    }
    let xdg = trimmed(environment, "XDG_CONFIG_HOME");
    if !xdg.is_empty() {
        return Ok(PathBuf::from(xdg.trim_end_matches('/')).join("svartal"));
    }
    let home = {
        let home = trimmed(environment, "HOME");
        if home.is_empty() { trimmed(environment, "USERPROFILE") } else { home }
    };
    if home.is_empty() {
        return Err(ConfigError(
            "Cannot find a home directory for the Svartal credential. Set SVARTAL_CONFIG_DIR."
                .to_string(),
        ));
    }
    Ok(PathBuf::from(home.trim_end_matches('/')).join(".config").join("svartal"))
}

fn parse_redirect(value: &str) -> Option<LoopbackRedirect> {
    if !is_allowed_redirect_uri(value) {
        return None;
    }
    let url = Url::parse(value).ok()?;
    let port = url.port_or_known_default()?;
    Some(LoopbackRedirect {
        redirect_uri: url.as_str().to_string(),
        host: url.host_str()?.to_string(),
        port,
        pathname: url.path().to_string(),
    })
}

/// The loopback callbacks this CLI may use, already filtered through the
/// provider's allowlist. An operator override is honoured only if Svartal
/// would accept it too — otherwise the CLI would fail later, at a point where
/// the message no longer explains the cause (`ID-7`, fail closed).
pub fn resolve_loopback_redirects(
    environment: &Environment,
) -> Result<Vec<LoopbackRedirect>, ConfigError> {
    let override_value = trimmed(environment, "SVARTAL_REDIRECT_URI");
    let candidates: Vec<String> = if override_value.is_empty() {
        REDIRECT_URIS.iter().map(|value| value.to_string()).collect()
    } else {
        vec![override_value.clone()]
    };
    let mut resolved: Vec<LoopbackRedirect> = Vec::new();
    for candidate in &candidates {
        if let Some(parsed) = parse_redirect(candidate)
            && !resolved.iter().any(|entry| entry.redirect_uri == parsed.redirect_uri)
        {
            resolved.push(parsed);
        }
    }
    if resolved.is_empty() {
        return Err(ConfigError(format!(
            "{override_value} is not a callback Svartal accepts. Use {} or {}.",
            REDIRECT_URIS[0], REDIRECT_URIS[1]
        )));
    }
    Ok(resolved)
}

pub fn resolve_config(environment: &Environment) -> Result<Config, ConfigError> {
    let client_id = {
        let value = trimmed(environment, "SVARTAL_CLIENT_ID");
        if value.is_empty() { CLIENT_ID.to_string() } else { value }
    };
    Ok(Config {
        issuer: resolve_issuer(environment),
        audience: resolve_audience(environment),
        client_id,
        scopes: SCOPES.iter().map(|scope| scope.to_string()).collect(),
        redirects: resolve_loopback_redirects(environment)?,
        relay_url: resolve_relay_url(environment),
        api_base_url: resolve_api_base_url(environment),
        state_directory: resolve_state_directory(environment)?,
    })
}
