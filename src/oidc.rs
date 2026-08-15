//! The OIDC client: discovery, the PKCE authorization-code flow, local token
//! verification, refresh, and revocation.
//!
//! This is a port of `WebOidcClient`
//! (`ivaldi/packages/svartal-client/src/identity/oidcClient.ts`), which is the
//! reference implementation of §1 of SVARTAL-CONNECT. Every rule below is
//! numbered there; the numbers in the comments are not decoration, they are
//! where the behaviour is specified.
//!
//! Two deliberate differences from the TypeScript client, both from being a
//! one-shot process rather than a long-lived web app:
//!
//! * the authorization transaction (`ID-11`) is a value this module hands back
//!   and takes again, not a storage entry. `ID-12` (consume before validating)
//!   is then structural: the caller moves it in and cannot use it twice.
//! * concurrent refreshes (`ID-24`) cannot happen inside one command, so there
//!   is no in-flight coalescing.

use std::collections::BTreeSet;

use serde_json::Value;
use url::Url;

use crate::config::{Config, LoopbackRedirect, is_allowed_redirect_uri, normalize_https_origin};
use crate::http::{HttpTransport, Request};
use crate::jwt::{Jwks, Jwt, b64url_encode, verify_rs256};
use crate::store::{StoredTokens, StoredUser, TokenStorage, parse_scope, same_scope, scope_is_subset};

/// `ID-13`: a callback is only accepted within ten minutes of starting the flow.
const CALLBACK_MAX_AGE_MS: i64 = 10 * 60 * 1_000;
/// `ID-23`: refresh five minutes before expiry, never on a 401.
const REFRESH_EARLY_MS: i64 = 5 * 60 * 1_000;
/// `ID-15`/`ID-16`: an hour is the longest token this client will accept.
const MAX_TOKEN_LIFETIME_SECONDS: i64 = 60 * 60;
const CLOCK_TOLERANCE_SECONDS: i64 = 60;
/// `ID-17`: an unknown `kid` may refetch the JWKS at most this often.
const JWKS_REFETCH_COOLDOWN_MS: i64 = 30 * 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Configuration,
    Metadata,
    Authorization,
    Callback,
    Token,
    Verification,
    Storage,
    Revocation,
}

/// `ID-26`: the two-value recovery hint. `Retry` keeps the session, `SignIn`
/// means the local session is gone and the person has to sign in again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    Retry,
    SignIn,
}

#[derive(Debug)]
pub struct OidcError {
    pub stage: Stage,
    pub message: String,
    pub recovery: Recovery,
}

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for OidcError {}

impl OidcError {
    fn new(stage: Stage, message: impl Into<String>, recovery: Recovery) -> Self {
        Self { stage, message: message.into(), recovery }
    }

    fn retry(stage: Stage, message: impl Into<String>) -> Self {
        Self::new(stage, message, Recovery::Retry)
    }
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

impl OidcConfig {
    /// The CLI configuration plus one chosen loopback callback. The client
    /// library holds the redirect URI in its configuration and checks every
    /// callback against it, so a CLI that may listen on either of two ports
    /// builds one client per port.
    pub fn from_cli(config: &Config, redirect: &LoopbackRedirect) -> Self {
        Self {
            issuer: config.issuer.clone(),
            audience: config.audience.clone(),
            client_id: config.client_id.clone(),
            redirect_uri: redirect.redirect_uri.clone(),
            scopes: config.scopes.clone(),
        }
    }

    fn validated(self) -> Result<Self, OidcError> {
        let issuer = normalize_https_origin(&self.issuer).ok_or_else(|| {
            OidcError::retry(Stage::Configuration, "The OIDC issuer must be an HTTPS origin.")
        })?;
        if !is_allowed_redirect_uri(&self.redirect_uri) {
            return Err(OidcError::retry(
                Stage::Configuration,
                "The web OIDC redirect URI must use HTTPS or the registered loopback development callback.",
            ));
        }
        let client_id = self.client_id.trim().to_string();
        let audience = self.audience.trim().to_string();
        let mut seen = BTreeSet::new();
        let scopes: Vec<String> = self
            .scopes
            .iter()
            .map(|scope| scope.trim().to_string())
            .filter(|scope| !scope.is_empty() && seen.insert(scope.clone()))
            .collect();
        if client_id.is_empty()
            || audience.is_empty()
            || scopes.is_empty()
            || !scopes.iter().any(|scope| scope == "openid")
        {
            return Err(OidcError::retry(
                Stage::Configuration,
                "The web OIDC client configuration is incomplete.",
            ));
        }
        Ok(Self { issuer, audience, client_id, redirect_uri: self.redirect_uri, scopes })
    }
}

#[derive(Debug, Clone)]
pub struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
    pub jwks_uri: String,
}

/// `ID-11`: the single-use authorization transaction.
#[derive(Debug, Clone)]
pub struct Transaction {
    pub state: String,
    pub nonce: String,
    pub verifier: String,
    pub created_at_epoch_ms: i64,
}

#[derive(Debug, Clone)]
pub struct Authorization {
    pub url: String,
    pub transaction: Transaction,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub access_token: String,
    pub user: StoredUser,
}

struct ExchangeOptions<'a> {
    allowed_scopes: &'a [String],
    expected_nonce: Option<&'a str>,
    expected_subject: Option<&'a str>,
    previous_refresh_token: Option<&'a str>,
}

pub struct OidcClient<'a> {
    pub config: OidcConfig,
    http: &'a dyn HttpTransport,
    storage: &'a dyn TokenStorage,
    now: &'a dyn Fn() -> i64,
    metadata: Option<Metadata>,
    jwks: Option<Jwks>,
    last_jwks_refresh_at_epoch_ms: Option<i64>,
}

impl<'a> OidcClient<'a> {
    pub fn new(
        config: OidcConfig,
        http: &'a dyn HttpTransport,
        storage: &'a dyn TokenStorage,
        now: &'a dyn Fn() -> i64,
    ) -> Result<Self, OidcError> {
        Ok(Self {
            config: config.validated()?,
            http,
            storage,
            now,
            metadata: None,
            jwks: None,
            last_jwks_refresh_at_epoch_ms: None,
        })
    }

    fn now_ms(&self) -> i64 {
        (self.now)()
    }

    // -- discovery ---------------------------------------------------------

    /// `ID-9`: discovery, with the issuer and every endpoint pinned to the
    /// configured origin. A document that points an endpoint somewhere else is
    /// refused, not followed.
    pub fn metadata(&mut self) -> Result<Metadata, OidcError> {
        if let Some(metadata) = &self.metadata {
            return Ok(metadata.clone());
        }
        let url = format!("{}/.well-known/openid-configuration", self.config.issuer);
        let response = self
            .http
            .send(Request::get(url))
            .map_err(|error| OidcError::retry(Stage::Metadata, format!("Could not validate OIDC discovery: {error}")))?;
        if !response.is_success() {
            return Err(OidcError::retry(
                Stage::Metadata,
                format!("OIDC discovery returned HTTP {}.", response.status),
            ));
        }
        let body = response
            .json()
            .map_err(|_| OidcError::retry(Stage::Metadata, "Could not validate OIDC discovery."))?;
        let issuer = required_string(&body, "issuer")
            .ok_or_else(|| OidcError::retry(Stage::Metadata, "Could not validate OIDC discovery."))?
            .trim_end_matches('/')
            .to_string();
        if issuer != self.config.issuer {
            return Err(OidcError::retry(Stage::Metadata, "OIDC discovery issuer mismatch."));
        }
        let metadata = Metadata {
            issuer,
            authorization_endpoint: self.provider_endpoint(&body, "authorization_endpoint")?,
            token_endpoint: self.provider_endpoint(&body, "token_endpoint")?,
            revocation_endpoint: self.provider_endpoint(&body, "revocation_endpoint")?,
            jwks_uri: self.provider_endpoint(&body, "jwks_uri")?,
        };
        self.metadata = Some(metadata.clone());
        Ok(metadata)
    }

    fn provider_endpoint(&self, body: &Value, name: &str) -> Result<String, OidcError> {
        let invalid = || {
            OidcError::retry(
                Stage::Metadata,
                format!("{name} must be HTTPS on the configured issuer origin."),
            )
        };
        let value = required_string(body, name).ok_or_else(invalid)?;
        let endpoint = Url::parse(value).map_err(|_| invalid())?;
        let issuer = Url::parse(&self.config.issuer).map_err(|_| invalid())?;
        if endpoint.scheme() != "https"
            || endpoint.origin() != issuer.origin()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(invalid());
        }
        Ok(endpoint.to_string())
    }

    // -- authorization -----------------------------------------------------

    /// `ID-10`: the authorization request. `state`, `nonce` and the PKCE
    /// verifier are each 32 random bytes, base64url without padding, and the
    /// challenge is their SHA-256.
    pub fn begin_authorization(&mut self) -> Result<Authorization, OidcError> {
        let metadata = self.metadata()?;
        let verifier = random_b64url(32)?;
        let challenge = b64url_encode(&sha256(verifier.as_bytes()));
        let state = random_b64url(32)?;
        let nonce = random_b64url(32)?;
        let mut url = Url::parse(&metadata.authorization_endpoint).map_err(|_| {
            OidcError::retry(Stage::Authorization, "The OIDC authorization endpoint is not a URL.")
        })?;
        {
            // Parameter order matches the reference client, so a URL printed by
            // `--no-browser` can be compared with the npm CLI's byte for byte.
            let mut query = url.query_pairs_mut();
            query.clear();
            query.append_pair("client_id", &self.config.client_id);
            query.append_pair("redirect_uri", &self.config.redirect_uri);
            query.append_pair("response_type", "code");
            query.append_pair("scope", &self.config.scopes.join(" "));
            query.append_pair("state", &state);
            query.append_pair("nonce", &nonce);
            query.append_pair("code_challenge", &challenge);
            query.append_pair("code_challenge_method", "S256");
        }
        Ok(Authorization {
            url: url.to_string(),
            transaction: Transaction {
                state,
                nonce,
                verifier,
                created_at_epoch_ms: self.now_ms(),
            },
        })
    }

    /// `ID-12`/`ID-13`: the transaction is consumed by value, then every rule
    /// in `ID-13` is checked before the code is exchanged.
    pub fn complete_authorization(
        &mut self,
        transaction: Transaction,
        callback_url: &str,
    ) -> Result<Session, OidcError> {
        let age_ms = self.now_ms() - transaction.created_at_epoch_ms;
        if !(-CLOCK_TOLERANCE_SECONDS * 1_000..=CALLBACK_MAX_AGE_MS).contains(&age_ms) {
            return Err(OidcError::retry(
                Stage::Callback,
                "The OIDC authorization transaction has expired.",
            ));
        }
        let callback = Url::parse(callback_url).map_err(|_| {
            OidcError::retry(Stage::Callback, "The OIDC callback URI does not match the client.")
        })?;
        let redirect = Url::parse(&self.config.redirect_uri).map_err(|_| {
            OidcError::retry(Stage::Callback, "The OIDC callback URI does not match the client.")
        })?;
        let mismatch = || {
            OidcError::retry(Stage::Callback, "The OIDC callback URI does not match the client.")
        };
        if callback.origin() != redirect.origin()
            || callback.path() != redirect.path()
            || !callback.username().is_empty()
            || callback.password().is_some()
            || callback.fragment().is_some()
        {
            return Err(mismatch());
        }
        // Any query parameter baked into the redirect URI has to come back
        // exactly as it went out.
        for (name, _) in redirect.query_pairs() {
            if query_values(&callback, &name) != query_values(&redirect, &name) {
                return Err(mismatch());
            }
        }
        let states = query_values(&callback, "state");
        if states.len() != 1 || states[0] != transaction.state {
            return Err(OidcError::retry(Stage::Callback, "The OIDC callback state is invalid."));
        }
        let provider_errors = query_values(&callback, "error");
        let codes = query_values(&callback, "code");
        if provider_errors.len() > 1
            || codes.len() > 1
            || (!provider_errors.is_empty() && !codes.is_empty())
        {
            return Err(OidcError::retry(
                Stage::Callback,
                "The OIDC callback response is ambiguous.",
            ));
        }
        if let Some(provider_error) = provider_errors.first() {
            return Err(OidcError::retry(
                Stage::Callback,
                format!("OIDC authorization failed: {provider_error}."),
            ));
        }
        let code = codes.first().ok_or_else(|| {
            OidcError::retry(Stage::Callback, "The OIDC callback has no authorization code.")
        })?;

        // `ID-14`: the code exchange.
        let scopes = self.config.scopes.clone();
        let tokens = self.exchange_token(
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri.clone()),
                ("client_id", &self.config.client_id.clone()),
                ("code_verifier", &transaction.verifier),
            ],
            ExchangeOptions {
                allowed_scopes: &scopes,
                expected_nonce: Some(&transaction.nonce),
                expected_subject: None,
                previous_refresh_token: None,
            },
        )?;
        Ok(session_of(&tokens))
    }

    // -- stored session ----------------------------------------------------

    /// The stored session, refreshed when it is within five minutes of expiry
    /// (`ID-23`) and re-verified locally otherwise.
    ///
    /// `Ok(None)` means nobody is signed in. `ID-21`: a stored set whose
    /// issuer or client id no longer matches the configuration is discarded
    /// rather than reused.
    pub fn existing_session(&mut self) -> Result<Option<Session>, OidcError> {
        let raw = self
            .storage
            .read()
            .map_err(|error| OidcError::retry(Stage::Storage, error.to_string()))?;
        let stored = raw.as_deref().and_then(StoredTokens::parse);
        let Some(stored) = stored else {
            self.clear_local()?;
            return Ok(None);
        };
        if stored.issuer != self.config.issuer || stored.client_id != self.config.client_id {
            self.clear_local()?;
            return Ok(None);
        }
        match self.verified_or_refreshed(&stored) {
            Ok(session) => Ok(Some(session)),
            Err(error) => {
                self.clear_local()?;
                Err(error)
            }
        }
    }

    fn verified_or_refreshed(&mut self, stored: &StoredTokens) -> Result<Session, OidcError> {
        if stored.access_expires_at_epoch_ms - REFRESH_EARLY_MS <= self.now_ms() {
            return Ok(session_of(&self.refresh(stored)?));
        }
        let audience = self.config.audience.clone();
        let client_id = self.config.client_id.clone();
        let access = self.verify_jwt(&stored.access_token, &audience, "access", None)?;
        let id = self.verify_jwt(&stored.id_token, &client_id, "id", None)?;
        let access_sub = access.claim_string("sub").unwrap_or_default().to_string();
        let id_sub = id.claim_string("sub").unwrap_or_default().to_string();
        if access_sub != id_sub || id_sub != stored.user.sub {
            return Err(OidcError::retry(
                Stage::Verification,
                "The stored OIDC token subjects do not match.",
            ));
        }
        let access_scopes = access
            .claim_string("scope")
            .and_then(parse_scope)
            .ok_or_else(|| OidcError::retry(Stage::Verification, "The stored OIDC token scopes are invalid."))?;
        if !same_scope(&access_scopes, &stored.scopes)
            || !scope_is_subset(&access_scopes, &self.config.scopes)
        {
            return Err(OidcError::retry(
                Stage::Verification,
                "The stored OIDC token scopes are invalid.",
            ));
        }
        Ok(session_of(stored))
    }

    /// `ID-24`/`ID-25`: refresh, with rotation and a stable subject required.
    fn refresh(&mut self, tokens: &StoredTokens) -> Result<StoredTokens, OidcError> {
        let client_id = self.config.client_id.clone();
        self.exchange_token(
            &[
                ("grant_type", "refresh_token"),
                ("refresh_token", &tokens.refresh_token),
                ("client_id", &client_id),
            ],
            ExchangeOptions {
                allowed_scopes: &tokens.scopes,
                expected_nonce: None,
                expected_subject: Some(&tokens.user.sub),
                previous_refresh_token: Some(&tokens.refresh_token),
            },
        )
    }

    /// `ID-27`: sign-out clears local storage first, then revokes. Returns
    /// whether there was a credential to remove at all.
    pub fn sign_out(&mut self) -> Result<bool, OidcError> {
        let raw = self
            .storage
            .read()
            .map_err(|error| OidcError::retry(Stage::Storage, error.to_string()))?;
        let tokens = raw.as_deref().and_then(StoredTokens::parse);
        let had_credential = raw.is_some();
        self.clear_local()?;
        let Some(tokens) = tokens else {
            return Ok(had_credential);
        };
        let metadata = self.metadata().map_err(|error| {
            OidcError::retry(
                Stage::Revocation,
                format!(
                    "The local session was removed, but the remote refresh token could not be revoked: {error}"
                ),
            )
        })?;
        let response = self
            .http
            .send(
                Request::post(metadata.revocation_endpoint).form(&[
                    ("token", tokens.refresh_token.as_str()),
                    ("token_type_hint", "refresh_token"),
                    ("client_id", self.config.client_id.as_str()),
                ]),
            )
            .map_err(|error| {
                OidcError::retry(
                    Stage::Revocation,
                    format!(
                        "The local session was removed, but the remote refresh token could not be revoked: {error}"
                    ),
                )
            })?;
        if !response.is_success() {
            return Err(OidcError::retry(
                Stage::Revocation,
                format!(
                    "The local session was removed, but the remote refresh token could not be revoked: OIDC revocation returned HTTP {}.",
                    response.status
                ),
            ));
        }
        Ok(had_credential)
    }

    fn clear_local(&mut self) -> Result<(), OidcError> {
        self.storage
            .remove()
            .map_err(|error| OidcError::retry(Stage::Storage, error.to_string()))
    }

    // -- token exchange ----------------------------------------------------

    fn exchange_token(
        &mut self,
        params: &[(&str, &str)],
        options: ExchangeOptions<'_>,
    ) -> Result<StoredTokens, OidcError> {
        let refreshing = options.previous_refresh_token.is_some();
        let on_invalid = if refreshing { Recovery::SignIn } else { Recovery::Retry };
        let metadata = self.metadata()?;
        let response =
            self.http.send(Request::post(metadata.token_endpoint).form(params)).map_err(|_| {
                OidcError::retry(Stage::Token, "The OIDC token endpoint is unavailable.")
            })?;
        if !response.is_success() {
            let oauth_error = response
                .json()
                .ok()
                .and_then(|body| body.get("error").and_then(Value::as_str).map(str::to_string));
            // `ID-26`: 5xx, 408, 425 and 429 are transient; anything else that
            // fails a *refresh* is terminal.
            let retryable = response.status >= 500
                || response.status == 408
                || response.status == 425
                || response.status == 429;
            let recovery =
                if refreshing && !retryable { Recovery::SignIn } else { Recovery::Retry };
            let message = if oauth_error.as_deref() == Some("invalid_grant") {
                "The OIDC refresh token is expired or revoked.".to_string()
            } else {
                format!("OIDC token exchange returned HTTP {}.", response.status)
            };
            return Err(OidcError::new(Stage::Token, message, recovery));
        }
        let body = response.json().map_err(|_| {
            OidcError::new(Stage::Token, "The OIDC token response is invalid JSON.", on_invalid)
        })?;
        let invalid = || OidcError::new(Stage::Token, "The OIDC token response is invalid.", on_invalid);

        // `ID-15`.
        let token_type = required_string(&body, "token_type").ok_or_else(invalid)?;
        let expires_in = body.get("expires_in").and_then(Value::as_i64).ok_or_else(invalid)?;
        if !token_type.eq_ignore_ascii_case("bearer")
            || expires_in <= 0
            || expires_in > MAX_TOKEN_LIFETIME_SECONDS
        {
            return Err(invalid());
        }
        let access_token = required_string(&body, "access_token").ok_or_else(invalid)?.to_string();
        let refresh_token = required_string(&body, "refresh_token").ok_or_else(invalid)?.to_string();
        let id_token = required_string(&body, "id_token").ok_or_else(invalid)?.to_string();
        let scopes = body
            .get("scope")
            .and_then(Value::as_str)
            .and_then(parse_scope)
            .ok_or_else(invalid)?;
        if !scope_is_subset(&scopes, options.allowed_scopes) {
            return Err(invalid());
        }
        // `ID-25`: a repeated refresh token is a hard failure.
        if options.previous_refresh_token == Some(refresh_token.as_str()) {
            return Err(invalid());
        }

        let audience = self.config.audience.clone();
        let client_id = self.config.client_id.clone();
        let verified = self
            .verify_jwt(&access_token, &audience, "access", None)
            .and_then(|access| {
                let id = self.verify_jwt(&id_token, &client_id, "id", options.expected_nonce)?;
                Ok((access, id))
            })
            .map_err(|error| {
                if refreshing {
                    OidcError::new(
                        Stage::Verification,
                        "The refreshed OIDC tokens could not be verified.",
                        Recovery::SignIn,
                    )
                } else {
                    error
                }
            })?;
        let (access_claims, id_claims) = verified;
        let access_sub = access_claims.claim_string("sub").unwrap_or_default().to_string();
        let id_sub = id_claims.claim_string("sub").unwrap_or_default().to_string();
        if access_sub != id_sub {
            return Err(OidcError::new(
                Stage::Verification,
                "The OIDC access and ID token subjects do not match.",
                on_invalid,
            ));
        }
        if let Some(expected) = options.expected_subject
            && access_sub != expected
        {
            return Err(OidcError::new(
                Stage::Verification,
                "The refreshed OIDC token subject changed.",
                Recovery::SignIn,
            ));
        }
        let access_scopes = access_claims
            .claim_string("scope")
            .and_then(parse_scope)
            .ok_or_else(|| {
                OidcError::new(
                    Stage::Verification,
                    "The OIDC access token and token response scopes do not match.",
                    on_invalid,
                )
            })?;
        if !same_scope(&access_scopes, &scopes) {
            return Err(OidcError::new(
                Stage::Verification,
                "The OIDC access token and token response scopes do not match.",
                on_invalid,
            ));
        }
        let user = user_of(&id_claims);
        if user.sub.trim().is_empty() {
            return Err(OidcError::new(
                Stage::Verification,
                "The OIDC ID token subject is missing.",
                on_invalid,
            ));
        }

        // `ID-18`: the effective expiry is the earlier of the token's own `exp`
        // and what `expires_in` promised.
        let jwt_expiry_ms = access_claims.claim_i64("exp").unwrap_or_default() * 1_000;
        let response_expiry_ms = self.now_ms() + expires_in * 1_000;
        let tokens = StoredTokens {
            version: 1,
            issuer: self.config.issuer.clone(),
            client_id: self.config.client_id.clone(),
            access_token,
            refresh_token,
            id_token,
            scopes,
            access_expires_at_epoch_ms: jwt_expiry_ms.min(response_expiry_ms),
            user,
        };
        self.storage.write(&tokens.to_json()).map_err(|error| {
            OidcError::new(
                Stage::Storage,
                format!("Could not store the Svartal Connect session: {error}"),
                on_invalid,
            )
        })?;
        Ok(tokens)
    }

    // -- verification ------------------------------------------------------

    /// `ID-16`: every claim checked locally, against JWKS, before the token is
    /// used for anything.
    fn verify_jwt(
        &mut self,
        token: &str,
        audience: &str,
        token_use: &str,
        expected_nonce: Option<&str>,
    ) -> Result<Jwt, OidcError> {
        let invalid_header =
            || OidcError::retry(Stage::Verification, "The OIDC token header is invalid.");
        let jwt = Jwt::parse(token).map_err(|_| invalid_header())?;
        if jwt.header_string("alg") != Some("RS256") {
            return Err(invalid_header());
        }
        let kid = jwt.header_string("kid").map(str::to_string).ok_or_else(invalid_header)?;
        if kid.trim().is_empty() {
            return Err(invalid_header());
        }

        let unverifiable =
            || OidcError::retry(Stage::Verification, "Could not verify the OIDC token.");
        let jwks = self.jwks_for_kid(&kid).map_err(|_| unverifiable())?;
        let key = jwks.find(&kid).ok_or_else(unverifiable)?;
        verify_rs256(&jwt, key).map_err(|_| unverifiable())?;

        let now_seconds = self.now_ms() / 1_000;
        if jwt.claim_string("iss") != Some(self.config.issuer.as_str())
            || jwt.claim_string("aud") != Some(audience)
        {
            return Err(unverifiable());
        }
        let (Some(issued_at), Some(expires_at)) = (jwt.claim_i64("iat"), jwt.claim_i64("exp"))
        else {
            return Err(unverifiable());
        };
        if expires_at <= issued_at
            || expires_at - issued_at > MAX_TOKEN_LIFETIME_SECONDS
            || issued_at > now_seconds + CLOCK_TOLERANCE_SECONDS
            || expires_at <= now_seconds - CLOCK_TOLERANCE_SECONDS
        {
            return Err(unverifiable());
        }
        if jwt.claim_string("sub").map(str::trim).unwrap_or_default().is_empty() {
            return Err(unverifiable());
        }
        if jwt.claim_string("token_use") != Some(token_use) {
            return Err(unverifiable());
        }
        if token_use == "access" && jwt.claim_string("client_id") != Some(self.config.client_id.as_str())
        {
            return Err(unverifiable());
        }
        if let Some(nonce) = expected_nonce
            && jwt.claim_string("nonce") != Some(nonce)
        {
            return Err(unverifiable());
        }
        Ok(jwt)
    }

    /// `ID-17`: fetch once and cache. On an unknown `kid`, refetch at most once
    /// per thirty seconds; if the key is still absent, fail. This bounds
    /// key-rotation churn without allowing a refetch loop.
    fn jwks_for_kid(&mut self, kid: &str) -> Result<Jwks, OidcError> {
        if self.jwks.is_none() {
            let fetched = self.fetch_jwks()?;
            self.jwks = Some(fetched);
        }
        let initial = self.jwks.clone().expect("jwks just set");
        if initial.find(kid).is_some() {
            return Ok(initial);
        }
        let now = self.now_ms();
        if let Some(last) = self.last_jwks_refresh_at_epoch_ms
            && now - last < JWKS_REFETCH_COOLDOWN_MS
        {
            return Err(OidcError::retry(
                Stage::Verification,
                format!("OIDC JWKS has no key for kid {kid}."),
            ));
        }
        self.last_jwks_refresh_at_epoch_ms = Some(now);
        let refreshed = self.fetch_jwks()?;
        self.jwks = Some(refreshed.clone());
        if refreshed.find(kid).is_none() {
            return Err(OidcError::retry(
                Stage::Verification,
                format!("OIDC JWKS has no key for kid {kid}."),
            ));
        }
        Ok(refreshed)
    }

    fn fetch_jwks(&mut self) -> Result<Jwks, OidcError> {
        let metadata = self.metadata()?;
        let failed = || OidcError::retry(Stage::Verification, "Could not read the OIDC JWKS.");
        let response = self.http.send(Request::get(metadata.jwks_uri)).map_err(|_| failed())?;
        if !response.is_success() {
            return Err(OidcError::retry(
                Stage::Verification,
                format!("OIDC JWKS returned HTTP {}.", response.status),
            ));
        }
        let body = response.json().map_err(|_| failed())?;
        Jwks::parse(&body).map_err(|_| failed())
    }
}

fn session_of(tokens: &StoredTokens) -> Session {
    Session { access_token: tokens.access_token.clone(), user: tokens.user.clone() }
}

fn user_of(id_token: &Jwt) -> StoredUser {
    let claim = |name: &str| {
        id_token
            .claim_string(name)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
    };
    StoredUser {
        sub: id_token.claim_string("sub").unwrap_or_default().to_string(),
        email: claim("email"),
        name: claim("name"),
        preferred_username: claim("preferred_username"),
        picture: claim("picture"),
    }
}

fn required_string<'v>(value: &'v Value, name: &str) -> Option<&'v str> {
    value.get(name).and_then(Value::as_str).filter(|text| !text.trim().is_empty())
}

fn query_values(url: &Url, name: &str) -> Vec<String> {
    url.query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
        .collect()
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// `ID-10`: 32 random bytes, base64url without padding.
fn random_b64url(size: usize) -> Result<String, OidcError> {
    let mut bytes = vec![0u8; size];
    getrandom::getrandom(&mut bytes).map_err(|_| {
        OidcError::retry(Stage::Authorization, "The system random source is unavailable.")
    })?;
    Ok(b64url_encode(&bytes))
}
