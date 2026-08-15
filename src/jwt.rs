//! JWT decoding and the RS256 signature check the OIDC tokens are verified
//! with (`ID-16`).
//!
//! The verification is local and mandatory: the CLI never treats a token as
//! good because the endpoint that issued it said so. The RSA implementation is
//! `ring`'s, which is the same code rustls already uses for TLS in this
//! binary, and it takes the JWKS `n`/`e` values directly, so no DER or PEM is
//! involved.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use serde_json::Value;

#[derive(Debug)]
pub struct JwtError(pub String);

impl std::fmt::Display for JwtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for JwtError {}

pub fn b64url_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value).ok()
}

#[derive(Debug, Clone)]
pub struct Jwt {
    pub header: Value,
    pub payload: Value,
    /// `header.payload`, the bytes the signature covers.
    pub signing_input: String,
    pub signature: Vec<u8>,
}

impl Jwt {
    pub fn parse(token: &str) -> Result<Self, JwtError> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return Err(JwtError("the token is not a compact JWS".to_string()));
        }
        let decode = |segment: &str, label: &str| -> Result<Value, JwtError> {
            let bytes = b64url_decode(segment)
                .ok_or_else(|| JwtError(format!("the token {label} is not base64url")))?;
            serde_json::from_slice(&bytes)
                .map_err(|_| JwtError(format!("the token {label} is not JSON")))
        };
        Ok(Self {
            header: decode(parts[0], "header")?,
            payload: decode(parts[1], "payload")?,
            signing_input: format!("{}.{}", parts[0], parts[1]),
            signature: b64url_decode(parts[2])
                .ok_or_else(|| JwtError("the token signature is not base64url".to_string()))?,
        })
    }

    pub fn header_string(&self, name: &str) -> Option<&str> {
        self.header.get(name).and_then(Value::as_str)
    }

    pub fn claim_string(&self, name: &str) -> Option<&str> {
        self.payload.get(name).and_then(Value::as_str)
    }

    pub fn claim_i64(&self, name: &str) -> Option<i64> {
        self.payload.get(name).and_then(Value::as_i64)
    }
}

/// One JSON Web Key Set, as fetched from `jwks_uri`.
#[derive(Debug, Clone)]
pub struct Jwks {
    pub keys: Vec<Value>,
}

impl Jwks {
    pub fn parse(value: &Value) -> Result<Self, JwtError> {
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| JwtError("the JWKS has no keys".to_string()))?;
        if keys.is_empty() {
            return Err(JwtError("the JWKS has no keys".to_string()));
        }
        Ok(Self { keys: keys.clone() })
    }

    pub fn find(&self, kid: &str) -> Option<&Value> {
        self.keys.iter().find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
    }
}

/// Verify an RS256 signature against one RSA JWK.
pub fn verify_rs256(jwt: &Jwt, jwk: &Value) -> Result<(), JwtError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("RSA") {
        return Err(JwtError("the signing key is not an RSA key".to_string()));
    }
    if let Some(algorithm) = jwk.get("alg").and_then(Value::as_str)
        && algorithm != "RS256"
    {
        return Err(JwtError("the signing key is not an RS256 key".to_string()));
    }
    let modulus = jwk
        .get("n")
        .and_then(Value::as_str)
        .and_then(b64url_decode)
        .ok_or_else(|| JwtError("the signing key modulus is invalid".to_string()))?;
    let exponent = jwk
        .get("e")
        .and_then(Value::as_str)
        .and_then(b64url_decode)
        .ok_or_else(|| JwtError("the signing key exponent is invalid".to_string()))?;
    let public_key = RsaPublicKeyComponents { n: modulus, e: exponent };
    public_key
        .verify(&RSA_PKCS1_2048_8192_SHA256, jwt.signing_input.as_bytes(), &jwt.signature)
        .map_err(|_| JwtError("the token signature is not valid".to_string()))
}
