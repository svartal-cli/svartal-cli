//! The persisted OIDC token set (`ID-19`, `ID-20`) and the file it lives in.
//!
//! The file is **the same file the npm CLI uses**:
//! `~/.config/svartal/svartal.oidc.tokens.v1.json`, same JSON shape, same
//! `0600` mode. Signing in with one CLI signs you in with the other, and
//! `logout` from either ends both. That is the whole reason the storage key
//! keeps its TypeScript name.

use std::cell::RefCell;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fsutil;

/// `ID-19`: the key the reference client persists the token set under. It is
/// the file's basename here.
pub const TOKEN_STORAGE_KEY: &str = "svartal.oidc.tokens.v1";

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
    /// corrupt credential file wants `sv login` to fix it, not a parse
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

// ---------------------------------------------------------------------------
// The Svartal API token `sv issue` authenticates with.

/// The OIDC access token only opens `/api/v1/client/*`. Everything under
/// `/api/v1` — projects, issues, transcripts — takes a Svartal API token, so
/// `sv` mints one from the signed-in session and keeps it in this file, beside
/// the OIDC token set, with the same `0600` discipline.
pub const API_TOKEN_STORAGE_KEY: &str = "svartal.api-token.v1";

/// One minted token: the id Svartal knows it by (for revocation on `sv
/// logout`), the secret that authenticates, and when Svartal will stop
/// accepting it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredApiToken {
    pub version: u8,
    pub id: String,
    pub secret: String,
    /// RFC 3339, as Svartal reported it. `None` when the answer carried no
    /// expiry; the token is then used until Svartal refuses it.
    pub expires_at: Option<String>,
}

/// A token this close to its expiry is minted again rather than sent: a
/// request that dies mid-command because the clock crossed the line is worse
/// than one extra mint.
const API_TOKEN_EXPIRY_MARGIN_MS: i64 = 5 * 60 * 1_000;

impl StoredApiToken {
    pub fn parse(raw: &str) -> Option<Self> {
        let token: Self = serde_json::from_str(raw).ok()?;
        if token.version != 1 || !non_empty(&token.id) || !non_empty(&token.secret) {
            return None;
        }
        Some(token)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Whether the token is worth sending at `now`. An expiry this program
    /// cannot read counts as usable: Svartal's answer, not a parse, decides.
    pub fn usable_at(&self, now_epoch_ms: i64) -> bool {
        match self.expires_at.as_deref().and_then(rfc3339_to_epoch_ms) {
            Some(expires_at) => now_epoch_ms + API_TOKEN_EXPIRY_MARGIN_MS < expires_at,
            None => true,
        }
    }
}

/// `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` to milliseconds since the
/// epoch. Only the shape Svartal emits (`DateTime.to_iso8601`) is accepted;
/// anything else is `None`, which the caller treats as "unknown".
pub fn rfc3339_to_epoch_ms(value: &str) -> Option<i64> {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || !matches!(bytes[10], b'T' | b't' | b' ') {
        return None;
    }
    let number = |from: usize, to: usize| -> Option<i64> { value.get(from..to)?.parse::<i64>().ok() };
    let (year, month, day) = (number(0, 4)?, number(5, 7)?, number(8, 10)?);
    let (hour, minute, second) = (number(11, 13)?, number(14, 16)?, number(17, 19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut rest = &value[19..];
    let mut millis = 0i64;
    if let Some(fraction) = rest.strip_prefix('.') {
        let digits: String = fraction.chars().take_while(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        let scaled = format!("{digits:0<3}");
        millis = scaled[..3].parse().ok()?;
        rest = &fraction[digits.len()..];
    }
    let offset_seconds = match rest {
        "Z" | "z" => 0,
        offset if offset.len() == 6 && (offset.starts_with('+') || offset.starts_with('-')) => {
            let sign = if offset.starts_with('-') { -1 } else { 1 };
            let hours: i64 = offset[1..3].parse().ok()?;
            let minutes: i64 = offset[4..6].parse().ok()?;
            if offset.as_bytes()[3] != b':' || hours > 23 || minutes > 59 {
                return None;
            }
            sign * (hours * 3_600 + minutes * 60)
        }
        _ => return None,
    };
    // Howard Hinnant's days-from-civil, the same arithmetic libc uses.
    let (y, m) = if month <= 2 { (year - 1, month + 9) } else { (year, month - 3) };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_seconds;
    Some(seconds * 1_000 + millis)
}

/// The API token file: `<state>/svartal.api-token.v1.json`.
pub struct ApiTokenFile {
    path: PathBuf,
}

impl ApiTokenFile {
    pub fn new(state_directory: &Path) -> Self {
        Self { path: state_directory.join(format!("{API_TOKEN_STORAGE_KEY}.json")) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The stored token, or `None` when there is no file — or a file that is
    /// not a token, which `sv` repairs by minting again.
    pub fn read(&self) -> Result<Option<StoredApiToken>, StoreError> {
        let bytes = fsutil::read_private_file(&self.path, MAX_TOKEN_FILE_BYTES)
            .map_err(|error| StoreError(error.to_string()))?;
        Ok(bytes.and_then(|bytes| String::from_utf8(bytes).ok()).as_deref().and_then(StoredApiToken::parse))
    }

    pub fn write(&self, token: &StoredApiToken) -> Result<(), StoreError> {
        fsutil::write_private_file(&self.path, token.to_json().as_bytes())
            .map_err(|error| StoreError(format!("could not store the Svartal API token: {error}")))
    }

    pub fn remove(&self) -> Result<(), StoreError> {
        fsutil::remove_file(&self.path)
            .map_err(|error| StoreError(format!("could not remove the Svartal API token: {error}")))
    }
}
