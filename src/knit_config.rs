//! Writing a Svartal credential into the knit CLI's user-global config.
//!
//! sv owns identity the way `gh` does for git: knit never talks to the OIDC
//! provider itself, it just finds a remote with a token already in place.
//! This module knows exactly two things about knit: where its user-global
//! `config.json` lives, and the `remotes` / `syncRemotes` shape inside it.

use std::path::PathBuf;

use serde_json::{Map, Value};

/// Knit's user-global config path, mirroring knit's own resolution order:
/// `$KNIT_HOME/config.json`, then `$XDG_CONFIG_HOME/knit/config.json`, then
/// `~/.config/knit/config.json`.
pub fn global_config_path() -> Result<PathBuf, String> {
    if let Some(home) = non_empty_env("KNIT_HOME") {
        return Ok(PathBuf::from(home).join("config.json"));
    }
    if let Some(xdg) = non_empty_env("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(xdg).join("knit").join("config.json"));
    }
    match non_empty_env("HOME") {
        Some(home) => Ok(PathBuf::from(home).join(".config").join("knit").join("config.json")),
        None => Err("Neither KNIT_HOME, XDG_CONFIG_HOME nor HOME is set; there is nowhere to write knit's config.".to_string()),
    }
}

fn non_empty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
}

/// What knit's config already says about a remote, so `sv login` knows
/// whether there is anything left to do.
#[derive(Debug, PartialEq)]
pub enum RemoteState {
    /// No remote of this name, or one without a token: configuring helps.
    Missing,
    /// The remote exists for this server with a token in place. Left alone —
    /// a person may have minted that token by hand with scopes a fresh
    /// default-scope token would silently lose.
    Configured,
    /// A same-named remote points at a different server. Not ours to touch.
    OtherServer { url: String },
}

/// Reads what the config at `path` says about `name` without changing it.
pub fn remote_state(path: &std::path::Path, name: &str, url: &str) -> RemoteState {
    let Ok(bytes) = std::fs::read(path) else { return RemoteState::Missing };
    let Ok(root) = serde_json::from_slice::<Value>(&bytes) else { return RemoteState::Missing };
    let Some(remote) = root.get("remotes").and_then(|remotes| remotes.get(name)) else {
        return RemoteState::Missing;
    };
    let existing_url = remote.get("url").and_then(Value::as_str).unwrap_or_default();
    if !existing_url.is_empty() && existing_url.trim_end_matches('/') != url.trim_end_matches('/') {
        return RemoteState::OtherServer { url: existing_url.to_string() };
    }
    let token = remote.get("token").and_then(Value::as_str).unwrap_or_default();
    if token.is_empty() { RemoteState::Missing } else { RemoteState::Configured }
}

/// What `install_remote` did, for the command to say out loud.
#[derive(Debug)]
pub struct Installed {
    pub replaced_token: bool,
    pub added_sync_remote: bool,
}

/// Puts `remotes[name] = {url, token}` into the config at `path` and makes
/// sure `syncRemotes` names it. Everything else in the file is preserved.
///
/// A same-named remote pointing at a different URL is refused rather than
/// repointed: that config was written on purpose by someone, possibly for a
/// different server, and silently redirecting sync traffic is worse than an
/// error.
pub fn install_remote(
    path: &std::path::Path,
    name: &str,
    url: &str,
    token: &str,
) -> Result<Installed, String> {
    let mut root = match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes).map_err(|error| {
            format!("{} is not valid JSON ({error}); not touching it.", path.display())
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Value::Object(Map::from_iter([(
                "schemaVersion".to_string(),
                Value::String("0.1".to_string()),
            )]))
        }
        Err(error) => return Err(format!("Could not read {}: {error}", path.display())),
    };

    let Some(object) = root.as_object_mut() else {
        return Err(format!("{} is not a JSON object; not touching it.", path.display()));
    };

    let remotes = object
        .entry("remotes")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .ok_or_else(|| format!("`remotes` in {} is not an object.", path.display()))?;

    let replaced_token = match remotes.get(name) {
        Some(existing) => {
            let existing_url = existing.get("url").and_then(Value::as_str).unwrap_or_default();
            if !existing_url.is_empty() && existing_url.trim_end_matches('/') != url.trim_end_matches('/') {
                return Err(format!(
                    "knit already has a remote named `{name}` pointing at {existing_url}. Remove it or rename it, then run this again."
                ));
            }
            true
        }
        None => false,
    };
    remotes.insert(
        name.to_string(),
        Value::Object(Map::from_iter([
            ("url".to_string(), Value::String(url.to_string())),
            ("token".to_string(), Value::String(token.to_string())),
        ])),
    );

    let sync_remotes = object
        .entry("syncRemotes")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .ok_or_else(|| format!("`syncRemotes` in {} is not an array.", path.display()))?;
    let added_sync_remote = !sync_remotes.iter().any(|entry| entry.as_str() == Some(name));
    if added_sync_remote {
        sync_remotes.push(Value::String(name.to_string()));
    }

    let body = serde_json::to_vec_pretty(&root)
        .map_err(|error| format!("Could not serialize knit config: {error}"))?;
    if let Some(parent) = path.parent() {
        crate::fsutil::ensure_state_directory(parent)
            .map_err(|error| format!("Could not create {}: {error}", parent.display()))?;
    }
    crate::fsutil::write_private_file(path, &body)
        .map_err(|error| format!("Could not write {}: {error}", path.display()))?;

    Ok(Installed { replaced_token, added_sync_remote })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sv-knit-config-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("config.json")
    }

    #[test]
    fn creates_a_fresh_config() {
        let path = temp_path("fresh");
        let _ = std::fs::remove_file(&path);
        let installed = install_remote(&path, "svartal", "https://svartal.com", "kht_x").unwrap();
        assert!(!installed.replaced_token);
        assert!(installed.added_sync_remote);
        let root: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(root["remotes"]["svartal"]["url"], "https://svartal.com");
        assert_eq!(root["remotes"]["svartal"]["token"], "kht_x");
        assert_eq!(root["syncRemotes"][0], "svartal");
        assert_eq!(root["schemaVersion"], "0.1");
    }

    #[test]
    fn refreshes_a_token_and_keeps_the_rest_of_the_file() {
        let path = temp_path("refresh");
        std::fs::write(
            &path,
            r#"{"schemaVersion":"0.1","advice":false,"remotes":{"svartal":{"url":"https://svartal.com","token":"old"}},"syncRemotes":["svartal"]}"#,
        )
        .unwrap();
        let installed = install_remote(&path, "svartal", "https://svartal.com", "new").unwrap();
        assert!(installed.replaced_token);
        assert!(!installed.added_sync_remote);
        let root: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(root["remotes"]["svartal"]["token"], "new");
        assert_eq!(root["advice"], false);
        assert_eq!(root["syncRemotes"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn refuses_to_repoint_a_remote_at_another_server() {
        let path = temp_path("conflict");
        std::fs::write(
            &path,
            r#"{"remotes":{"svartal":{"url":"https://other.example","token":"t"}}}"#,
        )
        .unwrap();
        let error = install_remote(&path, "svartal", "https://svartal.com", "new").unwrap_err();
        assert!(error.contains("other.example"), "{error}");
    }

    #[test]
    fn remote_state_reads_without_touching() {
        let path = temp_path("state");
        let _ = std::fs::remove_file(&path);
        assert_eq!(remote_state(&path, "svartal", "https://svartal.com"), RemoteState::Missing);

        std::fs::write(
            &path,
            r#"{"remotes":{"svartal":{"url":"https://svartal.com","token":"kht_x"}}}"#,
        )
        .unwrap();
        assert_eq!(remote_state(&path, "svartal", "https://svartal.com"), RemoteState::Configured);
        assert_eq!(
            remote_state(&path, "svartal", "https://svartal.com/"),
            RemoteState::Configured
        );

        std::fs::write(&path, r#"{"remotes":{"svartal":{"url":"https://svartal.com"}}}"#).unwrap();
        assert_eq!(remote_state(&path, "svartal", "https://svartal.com"), RemoteState::Missing);

        std::fs::write(
            &path,
            r#"{"remotes":{"svartal":{"url":"https://other.example","token":"t"}}}"#,
        )
        .unwrap();
        assert_eq!(
            remote_state(&path, "svartal", "https://svartal.com"),
            RemoteState::OtherServer { url: "https://other.example".to_string() }
        );
    }

    #[test]
    fn refuses_a_file_that_is_not_json() {
        let path = temp_path("mangled");
        std::fs::write(&path, "not json").unwrap();
        let error = install_remote(&path, "svartal", "https://svartal.com", "t").unwrap_err();
        assert!(error.contains("not valid JSON"), "{error}");
    }
}
