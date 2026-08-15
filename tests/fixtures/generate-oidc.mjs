// Generates the OIDC fixture: a JWKS, and RS256 tokens signed by `jose` — the
// same library ivaldi's `WebOidcClient` verifies with.
//
// The Rust client verifies these tokens locally (ID-16, ID-17) and drives the
// whole code exchange and refresh against them, so the fixture is what pins
// Rust's verification to real provider bytes rather than to its own signer.
//
// Source of truth for the claim set and the checks:
//   ivaldi packages/svartal-client/src/identity/oidcClient.ts
//   ivaldi packages/svartal-client/SVARTAL-CONNECT.md  §1.3, §1.4
//
// Every nondeterministic input is a constant here, but RSA signatures are not
// reproducible across regenerations (the key is generated fresh), so the
// fixture pins the key too.
//
// Usage:
//   node generate-oidc.mjs <output-dir> [package-with-jose]
import * as NodeFs from "node:fs/promises";
import { createRequire } from "node:module";
import * as NodePath from "node:path";

const out = NodePath.resolve(process.argv[2] ?? ".");
const josePackage = NodePath.resolve(
  process.argv[3] ??
    NodePath.join(import.meta.dirname, "..", "..", "..", "ivaldi", "packages", "svartal-cli"),
);
const { SignJWT, exportJWK, generateKeyPair } = createRequire(
  NodePath.join(josePackage, "package.json"),
)("jose");

const ISSUER = "https://api.example.test";
const RELAY = "https://relay.example.test";
const AUDIENCE = "t3-code-relay";
const CLIENT_ID = "svartal-cli";
const SUBJECT = "11111111-2222-3333-4444-555555555555";
const SCOPES = ["openid", "profile", "email", "offline_access"];
const KID = "key-1";

// A fixed instant the tests run at: 2026-07-30T12:00:00Z.
const NOW_SECONDS = 1_785_412_800;
const ISSUED_AT = NOW_SECONDS - 60;
const EXPIRES_AT = NOW_SECONDS + 3_000;
const NONCE = "fixture-nonce-U0mQ2sVrGkC8ZzWq1yYbXn4pLd7eTfHj";

const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
const publicJwk = await exportJWK(publicKey);

const sign = (claims, overrides = {}) =>
  new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: overrides.kid ?? KID })
    .setIssuer(overrides.issuer ?? ISSUER)
    .setSubject(overrides.subject ?? SUBJECT)
    .setIssuedAt(overrides.issuedAt ?? ISSUED_AT)
    .setExpirationTime(overrides.expiresAt ?? EXPIRES_AT)
    .sign(privateKey);

const accessToken = (overrides = {}) =>
  sign(
    {
      aud: overrides.audience ?? AUDIENCE,
      token_use: overrides.tokenUse ?? "access",
      client_id: overrides.clientId ?? CLIENT_ID,
      scope: (overrides.scopes ?? SCOPES).join(" "),
    },
    overrides,
  );

const idToken = (overrides = {}) =>
  sign(
    {
      aud: overrides.audience ?? CLIENT_ID,
      token_use: overrides.tokenUse ?? "id",
      scope: SCOPES.join(" "),
      preferred_username: "person",
      name: "A Person",
      email: "person@example.test",
      ...(overrides.nonce === null ? {} : { nonce: overrides.nonce ?? NONCE }),
    },
    overrides,
  );

const initialAccess = await accessToken();
const initialId = await idToken();
const refreshedAccess = await accessToken();
const refreshedId = await idToken({ nonce: null });

const fixture = {
  issuer: ISSUER,
  relayUrl: RELAY,
  audience: AUDIENCE,
  clientId: CLIENT_ID,
  subject: SUBJECT,
  scopes: SCOPES,
  nonce: NONCE,
  nowEpochMs: NOW_SECONDS * 1_000,
  accessExpiresAtEpochMs: EXPIRES_AT * 1_000,
  discovery: {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
  },
  jwks: { keys: [{ ...publicJwk, kid: KID, alg: "RS256", use: "sig" }] },
  initialTokenResponse: {
    token_type: "bearer",
    expires_in: 3_000,
    access_token: initialAccess,
    refresh_token: "refresh-token-1",
    id_token: initialId,
    scope: SCOPES.join(" "),
  },
  refreshedTokenResponse: {
    token_type: "bearer",
    expires_in: 3_000,
    access_token: refreshedAccess,
    refresh_token: "refresh-token-2",
    id_token: refreshedId,
    scope: SCOPES.join(" "),
  },
  // The stored credential shape (ID-20), as the npm CLI writes it.
  storedTokens: {
    version: 1,
    issuer: ISSUER,
    clientId: CLIENT_ID,
    accessToken: initialAccess,
    refreshToken: "refresh-token-1",
    idToken: initialId,
    scopes: SCOPES,
    accessExpiresAtEpochMs: EXPIRES_AT * 1_000,
    user: {
      sub: SUBJECT,
      email: "person@example.test",
      name: "A Person",
      preferredUsername: "person",
      picture: null,
    },
  },
  // ID-25: a refresh whose subject moved is a hard failure, not a new session.
  subjectChangedTokenResponse: {
    token_type: "bearer",
    expires_in: 3_000,
    access_token: await accessToken({ subject: "99999999-8888-7777-6666-555555555555" }),
    refresh_token: "refresh-token-3",
    id_token: await idToken({ subject: "99999999-8888-7777-6666-555555555555", nonce: null }),
    scope: SCOPES.join(" "),
  },
  rejected: {
    // Each of these is a token ID-16 requires the client to refuse.
    wrongAudience: await accessToken({ audience: "someone-else" }),
    wrongTokenUse: await accessToken({ tokenUse: "id" }),
    wrongClientId: await accessToken({ clientId: "t3-web" }),
    wrongIssuer: await accessToken({ issuer: "https://evil.example.test" }),
    expired: await accessToken({ issuedAt: NOW_SECONDS - 4_000, expiresAt: NOW_SECONDS - 400 }),
    tooLongLived: await accessToken({ issuedAt: ISSUED_AT, expiresAt: ISSUED_AT + 4_000 }),
    unknownKid: await accessToken({ kid: "key-2" }),
  },
};

await NodeFs.writeFile(NodePath.join(out, "oidc.json"), `${JSON.stringify(fixture, null, 2)}\n`);
console.log("oidc fixture written to", NodePath.join(out, "oidc.json"));
