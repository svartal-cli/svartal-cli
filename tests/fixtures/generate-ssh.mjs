// Generates the ssh-bridge fixture by driving the REAL TypeScript ssh-proxy
// (`ivaldi/packages/svartal-cli/src/sshProxy.ts` on `@svartal/client/remote`)
// against a stubbed relay, a stubbed workspace and a WebSocket double, and
// dumping everything that crossed a boundary:
//
//   * every HTTP request the connect chain makes (url, method, headers, body),
//   * every WebSocket frame the client sent, byte for byte,
//   * the server frames it was answered with, byte for byte,
//   * what reached stdout, what the exit status was, and what `known_hosts`
//     held afterwards,
//   * the `~/.ssh/config` block `sv ssh-setup` writes.
//
// That is the whole wire contract of `sv ssh-proxy`, recorded from the
// implementation rather than from a description of it. The Rust client has to
// produce the same requests and the same frames from the same answers.
//
// Sources, for when this needs re-reading:
//   ivaldi packages/svartal-client/docs/ssh-bridge.md      the frozen contract
//   ivaldi packages/svartal-cli/src/sshProxy.ts            the path
//   ivaldi packages/svartal-cli/src/sshSetup.ts            keys, known_hosts, config
//   ivaldi packages/contracts/src/sshBridge.ts             the codec
//
// Usage:
//   node generate-ssh.mjs <output-dir> [svartal-cli-dir]
import * as NodeFs from "node:fs";
import * as NodeFsPromises from "node:fs/promises";
import * as NodeOs from "node:os";
import { createRequire } from "node:module";
import * as NodePath from "node:path";
import { pathToFileURL } from "node:url";

const out = NodePath.resolve(process.argv[2] ?? ".");
const cliDir = NodePath.resolve(
  process.argv[3] ??
    NodePath.join(import.meta.dirname, "..", "..", "..", "ivaldi", "packages", "svartal-cli"),
);
const packages = NodePath.join(cliDir, "..");

// This file lives outside the ivaldi checkout, so a bare specifier would not
// resolve from here. Published packages are located through ivaldi's own
// resolver; the workspace packages are imported straight from their TypeScript
// sources, which is what the CLI's own build does anyway.
const requireFromIvaldi = createRequire(NodePath.join(cliDir, "package.json"));
const fromIvaldi = (specifier) => import(pathToFileURL(requireFromIvaldi.resolve(specifier)).href);
const fromSource = (...segments) => import(pathToFileURL(NodePath.join(packages, ...segments)).href);

const { importDpopKey } = await fromSource("shared", "src", "dpopProof.ts");
const { runSshProxy } = await fromSource("svartal-cli", "src", "sshProxy.ts");
const { sshConfigBlock, hostAlias, readKnownHosts } = await fromSource(
  "svartal-cli",
  "src",
  "sshSetup.ts",
);
const contracts = await fromSource("contracts", "src", "index.ts");
const Effect = await fromIvaldi("effect/Effect");
const Layer = await fromIvaldi("effect/Layer");
const Socket = await fromIvaldi("effect/unstable/socket/Socket");
const { FetchHttpClient } = await fromIvaldi("effect/unstable/http");

// Everything here is a fixture value. No real host, id, key or token appears.
const RELAY = "https://relay.example.com";
const HTTP_BASE = "https://workspace.example.com";
const WS_BASE = "wss://workspace.example.com";
const ENVIRONMENT_ID = "env-fixture-0001";
const SHORTNAME = "fixture";
const ALIAS = hostAlias(SHORTNAME);
const CONNECTION_ID = "c1a2b3d4e5f6a7b8";
const CLIENT_PUBLIC_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureClientKeyAAAAAAAAAAAAAAAAAAAAAAA person@laptop";
const HOST_PUBLIC_KEY =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyAAAAAAAAAAAAAAAAAAAAAAAAA svartal-workspace";
const PRIVATE_JWK = {
  kty: "EC",
  crv: "P-256",
  x: "gIM9Zyiqs6b9rsCD1rnUWlY4KdbMG0_ZoiN-o3R5-dE",
  y: "mXO03LW1mqi7gU76vC6EYr7p4SsPHAPY1eiQPt0IiSc",
  d: "E5fWojxBXygO15oCGp0gdiy1vZ71-cPnMnL-4Ttv6GI",
};

const TARGET = {
  environmentId: ENVIRONMENT_ID,
  label: "Primary",
  machineName: "workbench",
  linked: true,
  machinePresence: "unknown",
};

// The bytes the client types and the bytes the workspace answers with. Neither
// is valid UTF-8 all the way through, on purpose: an SSH binary packet is not
// text, and a client that decoded it would corrupt the transport.
const STDIN_CHUNKS = [
  [...Buffer.from("SSH-2.0-OpenSSH_9.6\r\n", "utf8")],
  [0x00, 0x00, 0x00, 0x0c, 0x0a, 0x14, 0xff, 0xfe, 0x80, 0x41],
];
const STDOUT_CHUNKS = [
  [...Buffer.from("SSH-2.0-OpenSSH_9.2p1 Debian-2\r\n", "utf8")],
  [0x00, 0x00, 0x01, 0x2c, 0x05, 0x14, 0xc3, 0x28, 0xff, 0x00],
];

const httpCalls = [];
const clientFrames = [];
const serverFrames = [];
const stdoutChunks = [];

const hex = (bytes) => Buffer.from(bytes).toString("hex");

const jsonResponse = (body) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

function proofClaims(proof) {
  return JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString("utf8"));
}

const stubbedFetch = async (input, init) => {
  const url = String(input);
  const headers = new Headers(init?.headers);
  const body =
    typeof init?.body === "string"
      ? init.body
      : init?.body === undefined || init.body === null
        ? ""
        : await new Response(init.body).text();
  httpCalls.push({
    url,
    method: init?.method ?? "GET",
    authorization: headers.get("authorization"),
    hasDpopProof: headers.get("dpop") !== null,
    // The proof itself is a fresh signature every run; its claims are what the
    // Rust side has to reproduce, so record those instead.
    dpopClaims: headers.get("dpop") ? proofClaims(headers.get("dpop")) : null,
    body,
  });
  if (url === `${RELAY}/v1/client/dpop-token`) {
    return jsonResponse({
      access_token: "relay-access-token",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "DPoP",
      expires_in: 300,
      scope: "environment:connect",
    });
  }
  if (url === `${RELAY}/v1/environments/${ENVIRONMENT_ID}/connect`) {
    return jsonResponse({
      environmentId: ENVIRONMENT_ID,
      endpoint: { httpBaseUrl: HTTP_BASE, wsBaseUrl: WS_BASE, providerKind: "cloudflare_tunnel" },
      credential: "environment-credential",
      expiresAt: "2026-08-19T12:05:00.000Z",
    });
  }
  if (url === `${HTTP_BASE}/oauth/token`) {
    return jsonResponse({
      access_token: "workspace-access-token",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "DPoP",
      expires_in: 300,
      // `terminal:operate` alone: nothing on this path looks a working
      // directory up, so the ssh bridge drops `orchestration:read`.
      scope: "terminal:operate",
    });
  }
  if (url === `${HTTP_BASE}/api/auth/websocket-ticket`) {
    return jsonResponse({ ticket: "ws-ticket-ssh-fixture", expiresAt: "2026-08-19T12:05:00.000Z" });
  }
  return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
};

/** The binary WebSocket double. Every byte in either direction is recorded. */
class TestWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  readyState = TestWebSocket.CONNECTING;
  binaryType = "blob";
  sent = [];
  listeners = new Map();

  constructor(url) {
    this.url = url;
  }
  addEventListener(type, listener) {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }
  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  }
  send(data) {
    const bytes = new Uint8Array(data);
    this.sent.push(bytes);
    clientFrames.push(hex(bytes));
  }
  close(code = 1000, reason = "") {
    if (this.readyState === TestWebSocket.CLOSED) return;
    this.readyState = TestWebSocket.CLOSED;
    this.emit("close", { code, reason, type: "close" });
  }
  open() {
    this.readyState = TestWebSocket.OPEN;
    this.emit("open", { type: "open" });
  }
  serverMessage(...frames) {
    const total = frames.reduce((sum, frame) => sum + frame.length, 0);
    const message = new Uint8Array(total);
    let offset = 0;
    for (const frame of frames) {
      message.set(frame, offset);
      offset += frame.length;
    }
    serverFrames.push(hex(message));
    this.emit("message", { data: message.buffer, type: "message" });
  }
  emit(type, event) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

const sockets = [];
const socketLayer = Layer.succeed(Socket.WebSocketConstructor, (url) => {
  const socket = new TestWebSocket(url);
  sockets.push(socket);
  return socket;
});

const sleep = () => new Promise((resolve) => setTimeout(resolve, 1));

async function waitForSocket() {
  for (let attempt = 0; attempt < 3_000; attempt += 1) {
    if (sockets[0]) return sockets[0];
    await sleep();
  }
  throw new Error("the client never opened a websocket");
}

async function waitForFrames(count) {
  for (let attempt = 0; attempt < 3_000; attempt += 1) {
    if (clientFrames.length >= count) return;
    await sleep();
  }
  throw new Error(`the client sent ${clientFrames.length} frames, expected ${count}`);
}

// The local end: scripted stdin, recorded stdout. `finish()` is the EOF that
// becomes a `STDIN_EOF` frame.
let stdinEnded = false;
const stdinQueue = [...STDIN_CHUNKS.map((chunk) => Uint8Array.from(chunk))];
const stdinWaiters = [];
const stdio = {
  input: {
    [Symbol.asyncIterator]: () => ({
      next: async () => {
        for (;;) {
          const value = stdinQueue.shift();
          if (value !== undefined) return { done: false, value };
          if (stdinEnded) return { done: true, value: undefined };
          await new Promise((resolve) => stdinWaiters.push(resolve));
        }
      },
      return: async () => ({ done: true, value: undefined }),
    }),
  },
  write: (bytes) => stdoutChunks.push(hex(bytes)),
  flush: async () => {},
  end: () => {
    stdinEnded = true;
    while (stdinWaiters.length > 0) stdinWaiters.pop()();
  },
};

const stateDirectory = NodeFs.mkdtempSync(NodePath.join(NodeOs.tmpdir(), "svartal-ssh-fixture-"));
const knownHostsFile = NodePath.join(stateDirectory, "known_hosts");
const key = await importDpopKey(PRIVATE_JWK);

const program = runSshProxy({
  relayUrl: RELAY,
  clientId: "svartal-cli",
  accessToken: "oidc-access-token",
  target: TARGET,
  dpopKey: key,
  publicKey: CLIENT_PUBLIC_KEY,
  clientName: "sv",
  knownHosts: { path: knownHostsFile, alias: ALIAS },
  stdio,
  clientMetadata: { label: "svartal CLI", deviceType: "desktop" },
}).pipe(
  Effect.provide(
    Layer.mergeAll(
      socketLayer,
      FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, stubbedFetch))),
    ),
  ),
);

const running = Effect.runPromise(program);

const socket = await waitForSocket();
socket.open();

// 1. OPEN, always first.
await waitForFrames(1);
// 2. READY, always the server's first frame. The client records the host key
//    before it pumps a single byte.
socket.serverMessage(
  contracts.encodeSshReadyFrame({
    connectionId: CONNECTION_ID,
    hostPublicKey: HOST_PUBLIC_KEY,
  }),
);
// 3. Both typed chunks become STDIN frames, then the EOF becomes STDIN_EOF.
await waitForFrames(1 + STDIN_CHUNKS.length);
stdio.end();
await waitForFrames(1 + STDIN_CHUNKS.length + 1);
// 4. Output, then the sshd's own status.
for (const chunk of STDOUT_CHUNKS) {
  socket.serverMessage(...contracts.encodeSshStdoutFrames(Uint8Array.from(chunk)));
}
socket.serverMessage(contracts.encodeSshExitFrame({ reason: "sshd_exited", exitCode: 0 }));

const outcome = await running;
const knownHosts = readKnownHosts(knownHostsFile);

// The other half of the feature: the block `sv ssh-setup` writes. Recorded with
// fixed paths so the Rust side can byte-match the text.
const configBlock = sshConfigBlock({
  alias: ALIAS,
  target: SHORTNAME,
  binary: "/usr/local/bin/sv",
  identityFile: "/home/person/.config/svartal/ssh/id_ed25519",
  knownHostsFile: "/home/person/.config/svartal/ssh/known_hosts",
});

await NodeFsPromises.writeFile(
  NodePath.join(out, "ssh.json"),
  `${JSON.stringify(
    {
      relayUrl: RELAY,
      httpBaseUrl: HTTP_BASE,
      wsBaseUrl: WS_BASE,
      environmentId: ENVIRONMENT_ID,
      shortname: SHORTNAME,
      alias: ALIAS,
      privateJwk: PRIVATE_JWK,
      target: TARGET,
      clientPublicKey: CLIENT_PUBLIC_KEY,
      hostPublicKey: HOST_PUBLIC_KEY,
      connectionId: CONNECTION_ID,
      socketUrl: socket.url,
      httpCalls,
      stdinChunks: STDIN_CHUNKS.map((chunk) => hex(chunk)),
      clientFrames,
      serverFrames,
      stdoutChunks,
      knownHosts,
      configBlock,
      outcome,
    },
    null,
    2,
  )}\n`,
);
NodeFs.rmSync(stateDirectory, { recursive: true, force: true });
console.log("ssh fixture written to", NodePath.join(out, "ssh.json"));
console.log(`  ${httpCalls.length} http calls, ${clientFrames.length} client frames`);
process.exit(0);
