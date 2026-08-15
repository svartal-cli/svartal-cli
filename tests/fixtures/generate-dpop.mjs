// Generates the DPoP fixture with the SAME TypeScript code the npm CLI signs
// its proofs with, so the Rust proof builder can be pinned to its bytes.
//
// Source of truth for the proof shape, the claim ORDER (the order is part of
// the signed bytes) and the thumbprint:
//   ivaldi packages/shared/src/dpopProof.ts  -> createDpopProof, generateDpopKey
//   ivaldi packages/shared/src/dpop.ts       -> computeDpopJwkThumbprint, verifyDpopProof
//   ivaldi packages/shared/src/dpopCommon.ts -> DpopPublicJwk, normalizeDpopHtu
//
// ECDSA as WebCrypto performs it is randomized, so a whole proof is NOT
// reproducible byte for byte the way brok's Ed25519 link proof is. What IS
// reproducible, and what the relay actually verifies over, is the signing
// input: `base64url(header).base64url(payload)`. The fixture therefore pins
// both halves of that string for every case, plus the full TypeScript proof so
// the Rust verifier can be checked against real TypeScript bytes.
//
// Usage:
//   node generate-dpop.mjs <output-dir> [ivaldi-shared-dir]
//   node generate-dpop.mjs --verify <rust-proofs.json> [ivaldi-shared-dir]
//
// The second mode closes the loop the other way: it runs ivaldi's real
// `verifyDpopProof` over proofs the Rust implementation produced.
import * as NodeFs from "node:fs/promises";
import * as NodePath from "node:path";

const argv = process.argv.slice(2);
const verifyMode = argv[0] === "--verify";
const sharedDir = NodePath.resolve(
  (verifyMode ? argv[2] : argv[1]) ??
    NodePath.join(import.meta.dirname, "..", "..", "..", "ivaldi", "packages", "shared"),
);

const { createDpopProof, importDpopKey } = await import(
  NodePath.join(sharedDir, "src", "dpopProof.ts")
);
const { verifyDpopProof, computeDpopJwkThumbprint } = await import(
  NodePath.join(sharedDir, "src", "dpop.ts")
);

// Throwaway fixture key. Never a real proof key: it exists in this file, in
// git, in a public repository.
const PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "gIM9Zyiqs6b9rsCD1rnUWlY4KdbMG0_ZoiN-o3R5-dE",
  y: "mXO03LW1mqi7gU76vC6EYr7p4SsPHAPY1eiQPt0IiSc",
  d: "E5fWojxBXygO15oCGp0gdiy1vZ71-cPnMnL-4Ttv6GI",
};

const key = await importDpopKey(PRIVATE_JWK);

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, "base64url").toString("utf8"));
}

if (verifyMode) {
  const path = NodePath.resolve(argv[1]);
  const document = JSON.parse(await NodeFs.readFile(path, "utf8"));
  let failed = 0;
  for (const entry of document.proofs) {
    const [, payload] = entry.proof.split(".");
    const iat = decodeSegment(payload).iat;
    const result = verifyDpopProof({
      proof: entry.proof,
      method: entry.method,
      url: entry.url,
      nowEpochSeconds: iat,
      expectedThumbprint: document.thumbprint,
      ...(entry.accessToken ? { expectedAccessToken: entry.accessToken } : {}),
    });
    if (result.ok) {
      console.log(`ok    ${entry.name}: verified, thumbprint ${result.thumbprint}`);
    } else {
      failed += 1;
      console.log(`FAIL  ${entry.name}: ${result.reason}`);
    }
  }
  console.log(`${document.proofs.length - failed}/${document.proofs.length} Rust proofs accepted by the TypeScript verifier`);
  process.exit(failed === 0 ? 0 : 1);
}

const out = NodePath.resolve(argv[0] ?? ".");

// Every nondeterministic input is a constant here.
const FIXED_IAT = 1_785_412_800; // 2026-07-30T12:00:00Z
const ACCESS_TOKEN = "fixture-relay-access-token";

const cases = [
  {
    name: "token-exchange",
    method: "POST",
    url: "https://relay.example.com/v1/client/dpop-token",
    jti: "7c1f0a2e-0000-4000-8000-000000001111",
    iat: FIXED_IAT,
  },
  {
    name: "connect-with-ath",
    method: "POST",
    url: "https://relay.example.com/v1/environments/env-fixture-0001/connect",
    accessToken: ACCESS_TOKEN,
    jti: "7c1f0a2e-0000-4000-8000-000000002222",
    iat: FIXED_IAT + 1,
  },
  {
    // htu drops the query and the fragment, and the method is upper-cased.
    name: "query-and-fragment-stripped",
    method: "get",
    url: "https://relay.example.com/v1/environments?cursor=2#anchor",
    jti: "7c1f0a2e-0000-4000-8000-000000003333",
    iat: FIXED_IAT + 2,
  },
];

const signed = [];
for (const testCase of cases) {
  const created = await createDpopProof(
    {
      method: testCase.method,
      url: testCase.url,
      key,
      ...(testCase.accessToken ? { accessToken: testCase.accessToken } : {}),
    },
    { jti: testCase.jti, now: () => testCase.iat * 1_000 },
  );
  const [header, payload] = created.proof.split(".");
  const verified = verifyDpopProof({
    proof: created.proof,
    method: testCase.method,
    url: testCase.url,
    nowEpochSeconds: testCase.iat,
    expectedThumbprint: created.thumbprint,
    ...(testCase.accessToken ? { expectedAccessToken: testCase.accessToken } : {}),
  });
  if (!verified.ok) {
    throw new Error(`the generator produced a proof its own verifier rejects: ${verified.reason}`);
  }
  signed.push({
    ...testCase,
    // The bytes the signature covers. This is what Rust must reproduce.
    signingInput: `${header}.${payload}`,
    header: decodeSegment(header),
    payload: decodeSegment(payload),
    proof: created.proof,
  });
}

await NodeFs.writeFile(
  NodePath.join(out, "dpop.json"),
  `${JSON.stringify(
    {
      privateJwk: PRIVATE_JWK,
      publicJwk: { kty: PRIVATE_JWK.kty, crv: PRIVATE_JWK.crv, x: PRIVATE_JWK.x, y: PRIVATE_JWK.y },
      thumbprint: computeDpopJwkThumbprint({
        kty: PRIVATE_JWK.kty,
        crv: PRIVATE_JWK.crv,
        x: PRIVATE_JWK.x,
        y: PRIVATE_JWK.y,
      }),
      accessToken: ACCESS_TOKEN,
      cases: signed,
    },
    null,
    2,
  )}\n`,
);
console.log("dpop fixture written to", NodePath.join(out, "dpop.json"));
