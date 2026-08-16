//! Short names for workspaces: the word a person types instead of a workspace
//! id.
//!
//! A workspace id is a machine's identifier, not a name anyone wants to type
//! twice. `sv name web env-9f3c…` records `web` once and every target argument
//! accepts it from then on.
//!
//! The file is `~/.config/svartal/shortnames.json`, next to the credential and
//! the DPoP key, `0600` in the `0700` state directory, written through a
//! temporary file and a rename like everything else this CLI persists. The
//! shape is deliberately the smallest thing that can be read by another
//! program — a flat map of name to workspace id, no version, no wrapper — so
//! the npm CLI can adopt the same file without a migration:
//!
//! ```json
//! { "web": "env-9f3c", "box": "env-11a2" }
//! ```
//!
//! Unlike the credential, a damaged entry here costs nothing: an entry whose
//! name or value is not usable is dropped and the rest of the file still
//! works. Refusing to resolve `web` because some other line is malformed would
//! be a worse trade than ignoring that line.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::fsutil;

/// The basename in the state directory. Shared with the npm CLI by intent.
pub const SHORTNAMES_FILE_NAME: &str = "shortnames.json";

/// A map of short words. Anything much larger is not one.
const MAX_SHORTNAMES_FILE_BYTES: u64 = 65_536;

/// `[a-z0-9][a-z0-9-]{0,31}`: 32 characters at most.
pub const MAX_SHORTNAME_LENGTH: usize = 32;

/// The rule, in the words the CLI says it with.
pub const SHORTNAME_RULE: &str = "A short name is 1 to 32 characters of lowercase letters, digits and dashes, and starts with a letter or a digit.";

#[derive(Debug)]
pub struct ShortnameError(pub String);

impl std::fmt::Display for ShortnameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ShortnameError {}

/// True for a name this CLI will store.
///
/// Lowercase only, because resolution lowercases what the person typed: a name
/// that only differs by case could never be told apart from the one it shadows.
pub fn is_valid_shortname(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SHORTNAME_LENGTH {
        return false;
    }
    if !matches!(bytes[0], b'a'..=b'z' | b'0'..=b'9') {
        return false;
    }
    bytes[1..].iter().all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
}

/// What an assignment displaced, so the command can say it out loud.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Assignment {
    /// The workspace this name pointed at before.
    pub replaced_environment: Option<String>,
    /// The name this workspace answered to before. One workspace keeps one
    /// name: two names for one workspace would make the SHORTNAME column in
    /// `sv envs` a choice rather than a fact.
    pub replaced_shortname: Option<String>,
}

/// The stored names, in memory. Sorted, so the file is stable across writes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shortnames {
    entries: BTreeMap<String, String>,
}

impl Shortnames {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read the file's JSON. Entries that are not `"name": "workspace id"` with
    /// a usable name are dropped; a file that is not an object at all reads as
    /// no names.
    pub fn parse(raw: &str) -> Self {
        let Ok(serde_json::Value::Object(object)) = serde_json::from_str::<serde_json::Value>(raw)
        else {
            return Self::new();
        };
        let mut entries = BTreeMap::new();
        for (name, value) in object {
            let Some(environment_id) = value.as_str() else { continue };
            let environment_id = environment_id.trim();
            if !is_valid_shortname(&name) || environment_id.is_empty() {
                continue;
            }
            entries.insert(name, environment_id.to_string());
        }
        Self { entries }
    }

    pub fn to_json(&self) -> String {
        let object: serde_json::Map<String, serde_json::Value> = self
            .entries
            .iter()
            .map(|(name, environment_id)| {
                (name.clone(), serde_json::Value::String(environment_id.clone()))
            })
            .collect();
        format!("{}\n", serde_json::to_string_pretty(&object).unwrap_or_else(|_| "{}".to_string()))
    }

    /// The workspace a name points at. The lookup is lowercased because
    /// resolution is.
    pub fn environment_of(&self, shortname: &str) -> Option<&str> {
        self.entries.get(&shortname.trim().to_lowercase()).map(String::as_str)
    }

    /// The name a workspace answers to, for the SHORTNAME column.
    pub fn shortname_of(&self, environment_id: &str) -> Option<&str> {
        let needle = environment_id.trim().to_lowercase();
        self.entries
            .iter()
            .find(|(_, value)| value.to_lowercase() == needle)
            .map(|(name, _)| name.as_str())
    }

    pub fn entries(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(name, value)| (name.as_str(), value.as_str()))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Record a name. Both directions are one-to-one: a name points at one
    /// workspace, and a workspace answers to one name.
    pub fn assign(
        &mut self,
        shortname: &str,
        environment_id: &str,
    ) -> Result<Assignment, ShortnameError> {
        let shortname = shortname.trim().to_lowercase();
        let environment_id = environment_id.trim().to_string();
        if !is_valid_shortname(&shortname) {
            return Err(ShortnameError(format!("{shortname} is not a usable name. {SHORTNAME_RULE}")));
        }
        if environment_id.is_empty() {
            return Err(ShortnameError("A name needs a workspace to point at.".to_string()));
        }
        let replaced_shortname = self
            .shortname_of(&environment_id)
            .filter(|existing| *existing != shortname)
            .map(str::to_string);
        if let Some(previous) = &replaced_shortname {
            self.entries.remove(previous);
        }
        let replaced_environment = self
            .entries
            .insert(shortname, environment_id.clone())
            .filter(|previous| *previous != environment_id);
        Ok(Assignment { replaced_environment, replaced_shortname })
    }

    /// Forget a name. Returns the workspace it pointed at.
    pub fn remove(&mut self, shortname: &str) -> Option<String> {
        self.entries.remove(&shortname.trim().to_lowercase())
    }
}

pub fn shortnames_path(state_directory: &Path) -> PathBuf {
    state_directory.join(SHORTNAMES_FILE_NAME)
}

/// The stored names, or none when the file is not there yet.
pub fn read_shortnames(state_directory: &Path) -> Result<Shortnames, ShortnameError> {
    let path = shortnames_path(state_directory);
    let bytes = fsutil::read_private_file(&path, MAX_SHORTNAMES_FILE_BYTES)
        .map_err(|error| ShortnameError(error.to_string()))?;
    match bytes {
        None => Ok(Shortnames::new()),
        Some(bytes) => match String::from_utf8(bytes) {
            Ok(raw) => Ok(Shortnames::parse(&raw)),
            Err(_) => Err(ShortnameError(format!("{} is not UTF-8", path.display()))),
        },
    }
}

pub fn write_shortnames(
    state_directory: &Path,
    shortnames: &Shortnames,
) -> Result<(), ShortnameError> {
    fsutil::write_private_file(&shortnames_path(state_directory), shortnames.to_json().as_bytes())
        .map_err(|error| ShortnameError(format!("could not store the workspace names: {error}")))
}
