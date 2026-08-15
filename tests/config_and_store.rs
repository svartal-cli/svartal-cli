//! Configuration resolution (`ID-6`, `ID-7`, `ID-8`) and the credential file.
//!
//! The file rules are the ones `ID-22` only recommends and the npm CLI adopts:
//! `0600`, owner-only directory, atomic replace. They are tested because the
//! two CLIs share the file.

use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use svartal::config::{
    Environment, is_allowed_redirect_uri, normalize_secure_relay_url, resolve_config,
    resolve_state_directory,
};
use svartal::store::{FileTokenStorage, StoredTokens, TokenStorage};

fn environment(pairs: &[(&str, &str)]) -> Environment {
    pairs.iter().map(|(name, value)| ((*name).to_string(), (*value).to_string())).collect()
}

fn temporary_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "svartal-test-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&path);
    path
}

// -- ID-6, ID-7, ID-8 ------------------------------------------------------

#[test]
fn only_https_or_the_two_registered_loopback_callbacks_are_allowed() {
    assert!(is_allowed_redirect_uri("https://app.example.com/auth/callback"));
    assert!(is_allowed_redirect_uri("http://127.0.0.1:5733/auth/callback"));
    assert!(is_allowed_redirect_uri("http://127.0.0.1:5734/auth/callback"));

    // ID-7: an unregistered loopback port fails closed.
    assert!(!is_allowed_redirect_uri("http://127.0.0.1:5735/auth/callback"));
    // ID-8: `localhost` is not `127.0.0.1`.
    assert!(!is_allowed_redirect_uri("http://localhost:5733/auth/callback"));
    // Credentials and fragments are refused whatever the scheme.
    assert!(!is_allowed_redirect_uri("https://user:pass@app.example.com/auth/callback"));
    assert!(!is_allowed_redirect_uri("https://app.example.com/auth/callback#fragment"));
    assert!(!is_allowed_redirect_uri("not a url"));
}

#[test]
fn the_default_configuration_is_the_hosted_one() {
    let config = resolve_config(&environment(&[("HOME", "/home/person")])).unwrap();
    assert_eq!(config.issuer, "https://api.svartal.com");
    assert_eq!(config.api_base_url, "https://api.svartal.com");
    assert_eq!(config.relay_url, "https://relay.svartal.com");
    assert_eq!(config.audience, "t3-code-relay");
    assert_eq!(config.client_id, "svartal-cli");
    assert_eq!(config.scopes, vec!["openid", "profile", "email", "offline_access"]);
    assert_eq!(
        config.redirects.iter().map(|entry| entry.port).collect::<Vec<_>>(),
        vec![5733, 5734]
    );
    assert_eq!(config.state_directory, PathBuf::from("/home/person/.config/svartal"));
}

#[test]
fn an_unusable_override_is_ignored_and_an_unusable_redirect_is_fatal() {
    // A relay URL that is not a bare HTTPS origin falls back to the default
    // rather than half-working.
    let config = resolve_config(&environment(&[
        ("HOME", "/home/person"),
        ("SVARTAL_RELAY_URL", "http://relay.example.com"),
    ]))
    .unwrap();
    assert_eq!(config.relay_url, "https://relay.svartal.com");
    assert_eq!(normalize_secure_relay_url("https://relay.example.com/v1"), None);
    assert_eq!(
        normalize_secure_relay_url("https://relay.example.com/").as_deref(),
        Some("https://relay.example.com")
    );

    let outcome = resolve_config(&environment(&[
        ("HOME", "/home/person"),
        ("SVARTAL_REDIRECT_URI", "http://127.0.0.1:9999/auth/callback"),
    ]));
    assert!(outcome.is_err());
}

#[test]
fn the_state_directory_follows_xdg_then_home() {
    assert_eq!(
        resolve_state_directory(&environment(&[("XDG_CONFIG_HOME", "/x/config/")])).unwrap(),
        PathBuf::from("/x/config/svartal")
    );
    assert_eq!(
        resolve_state_directory(&environment(&[("SVARTAL_CONFIG_DIR", "/somewhere/else")])).unwrap(),
        PathBuf::from("/somewhere/else")
    );
    assert!(resolve_state_directory(&environment(&[])).is_err());
}

// -- the credential file ---------------------------------------------------

#[test]
fn the_credential_file_is_owner_only_and_replaced_atomically() {
    let directory = temporary_directory("store");
    let storage = FileTokenStorage::new(&directory);
    assert!(storage.read().unwrap().is_none());

    storage.write("{\"first\":true}").unwrap();
    let mode = std::fs::metadata(storage.path()).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "the credential must not be readable by anyone else");
    let directory_mode = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o7777;
    assert_eq!(directory_mode, 0o700);

    storage.write("{\"second\":true}").unwrap();
    assert_eq!(storage.read().unwrap().unwrap(), "{\"second\":true}");
    // No temporary file survives a write.
    let leftovers: Vec<String> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
        .filter(|name| name.contains(".tmp"))
        .collect();
    assert!(leftovers.is_empty(), "left {leftovers:?} behind");

    storage.remove().unwrap();
    assert!(storage.read().unwrap().is_none());
    // Removing something already gone is not an error.
    storage.remove().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_credential_other_users_can_read_is_refused() {
    let directory = temporary_directory("store-mode");
    let storage = FileTokenStorage::new(&directory);
    storage.write("{}").unwrap();
    std::fs::set_permissions(storage.path(), std::fs::Permissions::from_mode(0o644)).unwrap();

    let error = storage.read().unwrap_err();
    assert!(error.to_string().contains("readable by other users"));
    let _ = std::fs::remove_dir_all(&directory);
}

#[test]
fn a_corrupt_credential_reads_as_nobody_signed_in() {
    for raw in [
        "not json",
        "{}",
        r#"{"version":2,"issuer":"https://a.test","clientId":"c","accessToken":"a","refreshToken":"r","idToken":"i","scopes":["openid"],"accessExpiresAtEpochMs":1,"user":{"sub":"s","email":null,"name":null,"preferredUsername":null,"picture":null}}"#,
        // An empty subject is not a subject.
        r#"{"version":1,"issuer":"https://a.test","clientId":"c","accessToken":"a","refreshToken":"r","idToken":"i","scopes":["openid"],"accessExpiresAtEpochMs":1,"user":{"sub":"  ","email":null,"name":null,"preferredUsername":null,"picture":null}}"#,
        // A duplicated scope is a malformed scope set.
        r#"{"version":1,"issuer":"https://a.test","clientId":"c","accessToken":"a","refreshToken":"r","idToken":"i","scopes":["openid","openid"],"accessExpiresAtEpochMs":1,"user":{"sub":"s","email":null,"name":null,"preferredUsername":null,"picture":null}}"#,
    ] {
        assert!(StoredTokens::parse(raw).is_none(), "{raw} parsed");
    }
}

#[test]
fn blank_profile_claims_are_null_not_empty() {
    let raw = r#"{"version":1,"issuer":"https://a.test","clientId":"c","accessToken":"a","refreshToken":"r","idToken":"i","scopes":["openid"],"accessExpiresAtEpochMs":1,"user":{"sub":"s","email":"   ","name":null,"preferredUsername":"person","picture":null}}"#;
    let stored = StoredTokens::parse(raw).unwrap();
    assert_eq!(stored.user.email, None);
    assert_eq!(stored.user.preferred_username.as_deref(), Some("person"));
}
