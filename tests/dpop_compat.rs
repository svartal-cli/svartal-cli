//! Byte compatibility of the DPoP proof with the TypeScript implementation.
//!
//! `tests/fixtures/dpop.json` is produced by ivaldi's real `createDpopProof`
//! (`packages/shared/src/dpopProof.ts`) with the key, `jti` and `iat` pinned.
//! ECDSA as WebCrypto performs it is randomized, so the *signature* cannot be
//! reproduced; the signing input can, and that is the part the relay verifies
//! over. If these tests fail, the relay would reject this CLI's proofs — or,
//! worse, accept a subtly different claim set.
//!
//! Regenerate with:
//!   node tests/fixtures/generate-dpop.mjs tests/fixtures <ivaldi>/packages/shared
//!
//! The other direction — the TypeScript verifier accepting Rust-made proofs —
//! is `writes_rust_proofs_for_the_typescript_verifier` below plus:
//!   SVARTAL_DPOP_PROOF_OUT=/tmp/rust-dpop.json cargo test --test dpop_compat
//!   node tests/fixtures/generate-dpop.mjs --verify /tmp/rust-dpop.json

use std::path::PathBuf;

use p256::ecdsa::signature::Verifier as _;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::{EncodedPoint, PublicKey};
use serde_json::{Value, json};

use svartal::dpop::{DpopKey, PrivateJwk, ProofRequest, PublicJwk, access_token_hash, jwk_thumbprint, normalize_htu};
use svartal::jwt::b64url_decode;

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dpop.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn key_from(fixture: &Value) -> DpopKey {
    let jwk: PrivateJwk = serde_json::from_value(fixture["privateJwk"].clone()).unwrap();
    DpopKey::from_private_jwk(&jwk).unwrap()
}

fn text(value: &Value, field: &str) -> String {
    value.get(field).and_then(Value::as_str).unwrap().to_string()
}

fn request_of<'a>(case: &'a Value) -> ProofRequest<'a> {
    ProofRequest {
        method: case["method"].as_str().unwrap(),
        url: case["url"].as_str().unwrap(),
        access_token: case.get("accessToken").and_then(Value::as_str),
        jti: case["jti"].as_str().unwrap(),
        issued_at_seconds: case["iat"].as_i64().unwrap(),
    }
}

#[test]
fn public_half_and_thumbprint_match_the_typescript_key() {
    let fixture = fixture();
    let key = key_from(&fixture);
    let expected: PublicJwk = serde_json::from_value(fixture["publicJwk"].clone()).unwrap();
    assert_eq!(key.public_jwk(), &expected);
    assert_eq!(key.thumbprint(), text(&fixture, "thumbprint"));
    assert_eq!(jwk_thumbprint(&expected), text(&fixture, "thumbprint"));
}

#[test]
fn signing_input_matches_typescript_byte_for_byte() {
    let fixture = fixture();
    let key = key_from(&fixture);
    for case in fixture["cases"].as_array().unwrap() {
        let proof = key.create_proof(&request_of(case)).unwrap();
        let signing_input = proof.rsplit_once('.').unwrap().0.to_string();
        assert_eq!(
            signing_input,
            text(case, "signingInput"),
            "signing input differs for case {}",
            text(case, "name")
        );
    }
}

#[test]
fn rust_verifies_a_typescript_signed_proof() {
    let fixture = fixture();
    let key = key_from(&fixture);
    let verifying_key = verifying_key_of(key.public_jwk());
    for case in fixture["cases"].as_array().unwrap() {
        let proof = text(case, "proof");
        let (signing_input, signature) = proof.rsplit_once('.').unwrap();
        let signature = Signature::from_slice(&b64url_decode(signature).unwrap()).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .unwrap_or_else(|error| panic!("case {}: {error}", text(case, "name")));
    }
}

#[test]
fn rust_signatures_verify_against_the_fixture_key() {
    let fixture = fixture();
    let key = key_from(&fixture);
    let verifying_key = verifying_key_of(key.public_jwk());
    for case in fixture["cases"].as_array().unwrap() {
        let proof = key.create_proof(&request_of(case)).unwrap();
        let (signing_input, signature) = proof.rsplit_once('.').unwrap();
        let decoded = b64url_decode(signature).unwrap();
        // ES256 is a raw `r||s` pair, never DER.
        assert_eq!(decoded.len(), 64, "case {}", text(case, "name"));
        let signature = Signature::from_slice(&decoded).unwrap();
        verifying_key.verify(signing_input.as_bytes(), &signature).unwrap();
    }
}

#[test]
fn claims_match_the_typescript_payload() {
    let fixture = fixture();
    let key = key_from(&fixture);
    for case in fixture["cases"].as_array().unwrap() {
        let proof = key.create_proof(&request_of(case)).unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        let header: Value = serde_json::from_slice(&b64url_decode(parts[0]).unwrap()).unwrap();
        let payload: Value = serde_json::from_slice(&b64url_decode(parts[1]).unwrap()).unwrap();
        assert_eq!(header, case["header"], "header differs for {}", text(case, "name"));
        assert_eq!(payload, case["payload"], "payload differs for {}", text(case, "name"));
    }
}

#[test]
fn ath_is_the_hash_of_the_access_token() {
    let fixture = fixture();
    let access_token = text(&fixture, "accessToken");
    let with_ath = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case.get("accessToken").is_some())
        .unwrap();
    assert_eq!(with_ath["payload"]["ath"].as_str().unwrap(), access_token_hash(&access_token));
}

#[test]
fn htu_drops_the_query_and_the_fragment() {
    assert_eq!(
        normalize_htu("https://relay.example.com/v1/environments?cursor=2#anchor").unwrap(),
        "https://relay.example.com/v1/environments"
    );
    assert_eq!(
        normalize_htu("https://relay.example.com").unwrap(),
        "https://relay.example.com/"
    );
    assert!(normalize_htu("not a url").is_none());
}

#[test]
fn refuses_a_key_file_whose_halves_disagree() {
    let fixture = fixture();
    let mut jwk: PrivateJwk = serde_json::from_value(fixture["privateJwk"].clone()).unwrap();
    jwk.x = fixture["privateJwk"]["y"].as_str().unwrap().to_string();
    assert!(DpopKey::from_private_jwk(&jwk).is_err());
}

#[test]
fn the_key_file_is_the_one_the_npm_cli_reads_and_writes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = std::env::temp_dir().join(format!(
        "svartal-dpop-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    let path = svartal::dpop::dpop_key_file_path(&directory);

    let created = svartal::dpop::load_or_create_key(&directory).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);

    // The same field set, in the same order, as `dpopKeyFile.ts` writes.
    let written = std::fs::read_to_string(&path).unwrap();
    let keys: Vec<String> = serde_json::from_str::<Value>(&written)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    assert_eq!(keys, vec!["kty", "crv", "x", "y", "d"]);
    assert!(written.starts_with(r#"{"kty":"EC","crv":"P-256","x":"#));

    // A second call reuses the key: a new thumbprint would silently invalidate
    // every token bound to the old one.
    let reloaded = svartal::dpop::load_or_create_key(&directory).unwrap();
    assert_eq!(reloaded.thumbprint(), created.thumbprint());

    // And a key the TypeScript CLI wrote loads as-is.
    let fixture = fixture();
    std::fs::write(&path, fixture["privateJwk"].to_string()).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let imported = svartal::dpop::load_or_create_key(&directory).unwrap();
    assert_eq!(imported.thumbprint(), text(&fixture, "thumbprint"));

    let _ = std::fs::remove_dir_all(&directory);
}

/// Writes the Rust-made proofs where `generate-dpop.mjs --verify` can read
/// them. Off by default: a test suite that needs Node to pass is a test suite
/// that stops running.
#[test]
fn writes_rust_proofs_for_the_typescript_verifier() {
    let Ok(destination) = std::env::var("SVARTAL_DPOP_PROOF_OUT") else { return };
    let fixture = fixture();
    let key = key_from(&fixture);
    let proofs: Vec<Value> = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let proof = key.create_proof(&request_of(case)).unwrap();
            let mut entry = json!({
                "name": text(case, "name"),
                "method": text(case, "method"),
                "url": text(case, "url"),
                "proof": proof,
            });
            if let Some(access_token) = case.get("accessToken") {
                entry
                    .as_object_mut()
                    .unwrap()
                    .insert("accessToken".to_string(), access_token.clone());
            }
            entry
        })
        .collect();
    let document = json!({ "thumbprint": key.thumbprint(), "proofs": proofs });
    std::fs::write(destination, serde_json::to_string_pretty(&document).unwrap()).unwrap();
}

fn verifying_key_of(jwk: &PublicJwk) -> VerifyingKey {
    let x = b64url_decode(&jwk.x).unwrap();
    let y = b64url_decode(&jwk.y).unwrap();
    let point = EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    VerifyingKey::from(PublicKey::from_sec1_bytes(point.as_bytes()).unwrap())
}
