//! The persisted OIDC token set (`ID-19`, `ID-20`) and the file it lives in.
//!
//! The file is **the same file the npm CLI uses**:
//! `~/.config/svartal/t3.web.oidc.tokens.v1.json`, same JSON shape, same
//! `0600` mode. Signing in with one CLI signs you in with the other, and
//! `logout` from either ends both. That is the whole reason the storage key
//! keeps its TypeScript name.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil;

/// `ID-19`: the key the reference client persists the token set under. It is
/// the file's basename here.
pub const TOKEN_STORAGE_KEY: &str = "t3.web.oidc.tokens.v1";

/// The token set is a few kilobytes. Anything much larger is not one.
const MAX_TOKEN_FILE_BYTES: u64 = 65_536;

#[derive(Debug)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StoreError {}

/// `ID-20`, `user`. Absent claims are null, never empty strings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredUser {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
    pub picture: Option<String>,
}

/// `ID-20`. Field order matches the TypeScript object literal, so a file
/// written here and a file written by the npm CLI differ in nothing but their
/// values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredTokens {
    pub version: u8,
    pub issuer: String,
    pub client_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: String,
    pub scopes: Vec<String>,
    pub access_expires_at_epoch_ms: i64,
    pub user: StoredUser,
}

fn nullable(value: Option<String>) -> Option<String> {
    value.filter(|text| !text.trim().is_empty())
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

/// RFC 6749 `scope`: space separated, each token from a restricted set, no
/// duplicates.
pub fn parse_scope(value: &str) -> Option<Vec<String>> {
    if value.trim().is_empty() {
        return None;
    }
    let scopes: Vec<String> =
        value.trim().split(' ').filter(|scope| !scope.is_empty()).map(str::to_string).collect();
    if scopes.iter().any(|scope| !is_scope_token(scope)) {
        return None;
    }
    for (index, scope) in scopes.iter().enumerate() {
        if scopes[..index].contains(scope) {
            return None;
        }
    }
    Some(scopes)
}

fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| byte == 0x21 || (0x23..=0x5b).contains(&byte) || (0x5d..=0x7e).contains(&byte))
}

/// Set equality, which is what the OIDC rules compare scopes with.
pub fn same_scope(left: &[String], right: &[String]) -> bool {
    left.len() == right.len() && left.iter().all(|scope| right.contains(scope))
}

pub fn scope_is_subset(candidate: &[String], allowed: &[String]) -> bool {
    candidate.iter().all(|scope| allowed.contains(scope))
}

impl StoredTokens {
    /// Parse a stored token set. Anything that is not exactly the shape in
    /// `ID-20` is `None`, which the caller treats as "not signed in" — the
    /// same fail-quiet the reference client applies, because a person with a
    /// corrupt credential file wants `svartal login` to fix it, not a parse
    /// error.
    pub fn parse(raw: &str) -> Option<Self> {
        let mut tokens: Self = serde_json::from_str(raw).ok()?;
        if tokens.version != 1 {
            return None;
        }
        if !non_empty(&tokens.issuer)
            || !non_empty(&tokens.client_id)
            || !non_empty(&tokens.access_token)
            || !non_empty(&tokens.refresh_token)
            || !non_empty(&tokens.id_token)
            || !non_empty(&tokens.user.sub)
        {
            return None;
        }
        parse_scope(&tokens.scopes.join(" "))?;
        tokens.user.email = nullable(tokens.user.email);
        tokens.user.name = nullable(tokens.user.name);
        tokens.user.preferred_username = nullable(tokens.user.preferred_username);
        tokens.user.picture = nullable(tokens.user.picture);
        Some(tokens)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Where the token set is kept. One implementation writes the shared file; the
/// other keeps it in memory for tests.
pub trait TokenStorage {
    fn read(&self) -> Result<Option<String>, StoreError>;
    fn write(&self, value: &str) -> Result<(), StoreError>;
    fn remove(&self) -> Result<(), StoreError>;
}

pub struct FileTokenStorage {
    path: PathBuf,
}

impl FileTokenStorage {
    pub fn new(state_directory: &Path) -> Self {
        Self { path: state_directory.join(format!("{TOKEN_STORAGE_KEY}.json")) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl TokenStorage for FileTokenStorage {
    fn read(&self) -> Result<Option<String>, StoreError> {
        let bytes = fsutil::read_private_file(&self.path, MAX_TOKEN_FILE_BYTES)
            .map_err(|error| StoreError(error.to_string()))?;
        match bytes {
            None => Ok(None),
            Some(bytes) => String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| StoreError("the Svartal credential file is not UTF-8".to_string())),
        }
    }

    fn write(&self, value: &str) -> Result<(), StoreError> {
        fsutil::write_private_file(&self.path, value.as_bytes())
            .map_err(|error| StoreError(format!("could not store the Svartal credential: {error}")))
    }

    fn remove(&self) -> Result<(), StoreError> {
        fsutil::remove_file(&self.path)
            .map_err(|error| StoreError(format!("could not remove the Svartal credential: {error}")))
    }
}

#[derive(Default)]
pub struct MemoryTokenStorage {
    value: RefCell<Option<String>>,
}

impl MemoryTokenStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_value(value: &str) -> Self {
        Self { value: RefCell::new(Some(value.to_string())) }
    }
}

impl TokenStorage for MemoryTokenStorage {
    fn read(&self) -> Result<Option<String>, StoreError> {
        Ok(self.value.borrow().clone())
    }

    fn write(&self, value: &str) -> Result<(), StoreError> {
        *self.value.borrow_mut() = Some(value.to_string());
        Ok(())
    }

    fn remove(&self) -> Result<(), StoreError> {
        *self.value.borrow_mut() = None;
        Ok(())
    }
}
