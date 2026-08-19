//! Filesystem discipline for the two secrets this CLI writes: the OIDC token
//! set and the DPoP signing key.
//!
//! `ID-22` leaves file mode unspecified and only *recommends* `0600`. The
//! TypeScript CLI takes the recommendation (`src/tokenStore.ts`,
//! `packages/shared/src/dpopKeyFile.ts`: mkdir `0700`, write `0600`, chmod
//! again because umask masks the create mode, rename into place). This module
//! is the same recipe with brok's extra rule on the read side: a credential
//! file that is not a private regular file is refused rather than read, so a
//! world-readable refresh token fails loudly instead of quietly working.
//!
//! Unix only, like brok. The CLI is a terminal tool for macOS and Linux.

use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// Owner read/write only. A refresh token in a world-readable file is a leak.
pub const PRIVATE_FILE_MODE: u32 = 0o600;
/// Owner-only directory, so a new file cannot be observed while it is written.
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

#[derive(Debug)]
pub struct FsError {
    pub reason: String,
    pub source: Option<std::io::Error>,
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.source {
            Some(source) => write!(f, "{}: {source}", self.reason),
            None => write!(f, "{}", self.reason),
        }
    }
}

impl std::error::Error for FsError {}

fn err(reason: impl Into<String>) -> FsError {
    FsError { reason: reason.into(), source: None }
}

fn io(reason: impl Into<String>, source: std::io::Error) -> FsError {
    FsError { reason: reason.into(), source: Some(source) }
}

/// Create the state directory (and its parents) if it is missing.
///
/// The leaf is created `0700`. An existing directory is left exactly as it is:
/// the TypeScript CLI does not re-mode it either, and a person who deliberately
/// shares a config directory should not have it changed under them.
pub fn ensure_state_directory(path: &Path) -> Result<(), FsError> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => Ok(()),
        Ok(_) => Err(err(format!("{} is not a directory", path.display()))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(PRIVATE_DIRECTORY_MODE)
            .create(path)
            .map_err(|error| io(format!("could not create {}", path.display()), error)),
        Err(error) => Err(io(format!("could not inspect {}", path.display()), error)),
    }
}

/// Write a `0600` file through a temporary name and rename it into place.
///
/// A refresh rotates the token (`ID-25`), so a torn write would leave a
/// credential that is neither the old one nor the new one — and the old one is
/// already dead by then. The temporary name carries random bytes rather than
/// the TypeScript CLI's fixed `.tmp` suffix, so two `sv` processes writing
/// at once cannot clobber each other's half-written file.
pub fn write_private_file(path: &Path, body: &[u8]) -> Result<(), FsError> {
    let parent = path.parent().ok_or_else(|| err(format!("{} has no parent directory", path.display())))?;
    ensure_state_directory(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| err(format!("{} is not a usable path", path.display())))?;
    let temporary = path.with_file_name(format!("{file_name}.tmp-{}", random_suffix()?));
    match write_new_private_file(&temporary, body) {
        Ok(()) => std::fs::rename(&temporary, path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            io("could not replace the file", error)
        }),
        Err(error) => {
            let _ = std::fs::remove_file(&temporary);
            Err(error)
        }
    }
}

fn write_new_private_file(path: &Path, body: &[u8]) -> Result<(), FsError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|error| io(format!("could not create {}", path.display()), error))?;
    file.write_all(body).map_err(|error| io("could not write the file", error))?;
    file.sync_all().map_err(|error| io("could not flush the file", error))?;
    // The create mode is masked by umask, so state it again.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|error| io("could not set the file mode", error))
}

/// Read a private file. `Ok(None)` means it is not there yet.
///
/// A file that exists but is a symlink, a device, or readable by anyone else is
/// an error: the whole point of the mode is that nothing else on the box can
/// read the credential, and silently reading it anyway would hide the breach.
pub fn read_private_file(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, FsError> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io(format!("could not inspect {}", path.display()), error)),
    };
    if !meta.file_type().is_file() {
        return Err(err(format!("{} is not a regular file", path.display())));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(err(format!(
            "{} is readable by other users. Run `chmod 600 {}` or delete it and sign in again.",
            path.display(),
            path.display()
        )));
    }
    if meta.len() > max_bytes {
        return Err(err(format!("{} is larger than {max_bytes} bytes", path.display())));
    }
    std::fs::read(path)
        .map(Some)
        .map_err(|error| io(format!("could not read {}", path.display()), error))
}

/// Remove a file. A file that is already gone is not an error.
pub fn remove_file(path: &Path) -> Result<(), FsError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io(format!("could not remove {}", path.display()), error)),
    }
}

/// Random hex, for a name or a token nothing else will pick.
pub(crate) fn random_suffix() -> Result<String, FsError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|_| err("the system random source is unavailable"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
