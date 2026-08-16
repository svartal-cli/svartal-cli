// Generates the shell fixture by driving the REAL TypeScript shell path
// (`ivaldi/packages/svartal-cli/src/shell.ts` on `@svartal/client/remote`)
// against a stubbed relay, a stubbed workspace and a WebSocket double, and
// dumping everything that crossed a boundary:
//
//   * every HTTP request the connect chain makes (url, method, headers, body),
//   * every WebSocket frame the client sends,
//   * the server frames it was answered with.
//
// That is the whole wire contract of `svartal shell`, recorded from the
// implementation rather than from a description of it. The Rust client has to
// produce the same requests and the same frames from the same answers.
//
// Sources, for when this needs re-reading:
//   ivaldi packages/svartal-cli/src/shell.ts               the path
//   ivaldi packages/svartal-client/src/remote/connect.ts   token + ticket + socket
//   ivaldi packages/client-runtime/src/rpc/session.ts      the RPC session
//   effect/unstable/rpc/RpcMessage.ts                      the message shapes
//
// Usage:
//   node generate-shell.mjs <output-dir> [svartal-cli-dir]
import * as NodeFs from "node:fs/promises";
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
// sources, which is what the CLI's own build does anyway. Node >= 24 strips the
// types on the way in.
const requireFromIvaldi = createRequire(NodePath.join(cliDir, "package.json"));
const fromIvaldi = (specifier) => import(pathToFileURL(requireFromIvaldi.resolve(specifier)).href);
const fromSource = (...segments) => import(pathToFileURL(NodePath.join(packages, ...segments)).href);

const { importDpopKey } = await fromSource("shared", "src", "dpopProof.ts");
const { openShellSession, runShellPump, detachedTerminalId } = await fromSource(
  "svartal-cli",
  "src",
  "shell.ts",
);
const { rpcSessionLayer } = await fromSource("svartal-client", "src", "remote", "index.ts");
const contracts = await fromSource("contracts", "src", "index.ts");
const Effect = await fromIvaldi("effect/Effect");
const Layer = await fromIvaldi("effect/Layer");
const Socket = await fromIvaldi("effect/unstable/socket/Socket");
const { FetchHttpClient } = await fromIvaldi("effect/unstable/http");
const Schema = await fromIvaldi("effect/Schema");

// The wire carries the ENCODED form of these schemas, which is what a real
// server would send and what the Rust client parses.
const encodeServerConfig = Schema.encodeSync(contracts.ServerConfig);
const encodeSnapshot = Schema.encodeSync(contracts.TerminalSessionSnapshot);

// Everything here is a fixture value. No real host, id or token appears.
const RELAY = "https://relay.example.com";
const HTTP_BASE = "https://workspace.example.com";
const WS_BASE = "wss://workspace.example.com";
const ENVIRONMENT_ID = "env-fixture-0001";
const SUBJECT = "11111111-2222-3333-4444-555555555555";
const WORKSPACE_CWD = "/home/person/workspace";
const SIZE = { cols: 120, rows: 40 };
// The client forwards its own TERM so the remote PTY is spawned as the terminal
// the person is looking at. Pinned here so the fixture records the field.
const TERM = "xterm-ghostty";
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

const httpCalls = [];
const clientFrames = [];
const serverFrames = [];

const jsonResponse = (body) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
  });

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
      expiresAt: "2026-07-30T12:05:00.000Z",
    });
  }
  if (url === `${HTTP_BASE}/oauth/token`) {
    return jsonResponse({
      access_token: "workspace-access-token",
      issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
      token_type: "Bearer",
      expires_in: 300,
      scope: "terminal:operate orchestration:read",
    });
  }
  if (url === `${HTTP_BASE}/api/auth/websocket-ticket`) {
    return jsonResponse({ ticket: "ws-ticket-fixture", expiresAt: "2026-07-30T12:05:00.000Z" });
  }
  return new Response("{}", { status: 404, headers: { "content-type": "application/json" } });
};

function proofClaims(proof) {
  return JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString("utf8"));
}

/** The same WebSocket double the client package's own tests use. */
class TestWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  readyState = TestWebSocket.CONNECTING;
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
    this.sent.push(data);
    clientFrames.push(JSON.parse(data));
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
  serverMessage(value) {
    serverFrames.push(value);
    this.emit("message", { data: JSON.stringify(value), type: "message" });
  }
  emit(type, event) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }
}

const sockets = [];
const socketLayer = Layer.succeed(Socket.WebSocketConstructor, (url) => {
  const socket = new TestWebSocket(url);
  sockets.push(socket);
  queueMicrotask(() => socket.open());
  return socket;
});

const sleep = () => new Promise((resolve) => setTimeout(resolve, 1));

async function waitForRequest(tag) {
  for (let attempt = 0; attempt < 3_000; attempt += 1) {
    const socket = sockets[0];
    if (socket) {
      const found = socket.sent
        .map((raw) => JSON.parse(raw))
        .find((message) => message._tag === "Request" && message.tag === tag);
      if (found) return found;
    }
    await sleep();
  }
  throw new Error(
    `the client never sent a ${tag} request; it sent: ${(sockets[0]?.sent ?? [])
      .map((raw) => JSON.parse(raw).tag ?? JSON.parse(raw)._tag)
      .join(", ")}`,
  );
}

const succeed = (requestId, value) =>
  sockets[0].serverMessage({ _tag: "Exit", requestId: String(requestId), exit: { _tag: "Success", value } });
const chunk = (requestId, values) =>
  sockets[0].serverMessage({ _tag: "Chunk", requestId: String(requestId), values });

const SERVER_CONFIG = {
  environment: {
    environmentId: ENVIRONMENT_ID,
    label: "Primary",
    platform: { os: "linux", arch: "arm64" },
    serverVersion: "0.0.0-fixture",
    capabilities: { repositoryIdentity: true, connectionProbe: true },
  },
  auth: {
    policy: "loopback-browser",
    bootstrapMethods: ["one-time-token"],
    sessionMethods: ["dpop-access-token"],
    sessionCookieName: "t3_session",
  },
  cwd: WORKSPACE_CWD,
  keybindingsConfigPath: `${WORKSPACE_CWD}/keybindings.json`,
  keybindings: [],
  issues: [],
  providers: [],
  availableEditors: [],
  observability: {
    logsDirectoryPath: "/tmp/logs",
    localTracingEnabled: false,
    otlpTracesEnabled: false,
    otlpMetricsEnabled: false,
  },
  settings: contracts.DEFAULT_SERVER_SETTINGS,
};

const TERMINAL_ID = detachedTerminalId("shell", ENVIRONMENT_ID);
const THREAD_ID = `svartal-shell:${SUBJECT}`;

const snapshot = (values) => ({
  threadId: THREAD_ID,
  terminalId: TERMINAL_ID,
  cwd: WORKSPACE_CWD,
  worktreePath: null,
  status: "starting",
  pid: null,
  history: "",
  exitCode: null,
  exitSignal: null,
  label: "shell",
  updatedAt: "2026-07-30T12:00:00.000Z",
  ...values,
});

/**
 * Yields each scripted value once, then stays open — a real terminal does not
 * close because nobody is typing. `return` resolves so the pump's loser fibers
 * can be interrupted; a bare `async function*` suspended on a never-settling
 * await cannot be, and the program would hang instead of finishing.
 */
function scriptedIterable(values, delayMs) {
  return {
    [Symbol.asyncIterator]: () => {
      let index = 0;
      return {
        next: () =>
          index < values.length
            ? new Promise((resolve) => {
                const value = values[index];
                index += 1;
                setTimeout(() => resolve({ done: false, value }), delayMs);
              })
            : new Promise(() => {}),
        return: () => Promise.resolve({ done: true, value: undefined }),
      };
    },
  };
}

// A local terminal that types one line and resizes once, so the pump runs its
// whole shape: attach, write, resize, exit.
const typed = ["echo hello\r"];
const resizes = [{ cols: 100, rows: 30 }];
const written = [];
const localTerminal = {
  interactive: true,
  size: () => SIZE,
  input: scriptedIterable(typed, 1),
  resizes: scriptedIterable(resizes, 20),
  write: (data) => written.push(data),
  begin: () => () => {},
};

const key = await importDpopKey(PRIVATE_JWK);

const program = Effect.gen(function* () {
  const session = yield* openShellSession({
    relayUrl: RELAY,
    clientId: "svartal-cli",
    accessToken: "oidc-access-token",
    subject: SUBJECT,
    target: TARGET,
    dpopKey: key,
    size: SIZE,
    term: TERM,
    clientMetadata: { label: "svartal CLI", deviceType: "desktop" },
  });
  const outcome = yield* runShellPump({
    session,
    terminal: localTerminal,
    label: TARGET.label,
    subject: SUBJECT,
  });
  return { session, outcome };
}).pipe(
  Effect.scoped,
  Effect.provide(
    Layer.mergeAll(
      rpcSessionLayer.pipe(Layer.provide(socketLayer)),
      FetchHttpClient.layer.pipe(Layer.provide(Layer.succeed(FetchHttpClient.Fetch, stubbedFetch))),
    ),
  ),
);

const running = Effect.runPromise(program);

// Answer the RPC calls in the order the client makes them.
const configRequest = await waitForRequest("server.getConfig");
succeed(configRequest.id, encodeServerConfig(SERVER_CONFIG));

const openRequest = await waitForRequest("terminal.open");
succeed(openRequest.id, encodeSnapshot(snapshot({})));

const attachRequest = await waitForRequest("terminal.attach");
chunk(attachRequest.id, [
  { type: "snapshot", snapshot: encodeSnapshot(snapshot({ history: "previous output\r\n" })) },
]);
chunk(attachRequest.id, [
  { threadId: THREAD_ID, terminalId: TERMINAL_ID, type: "output", data: "hello\r\n" },
]);

// The write and the resize the local terminal produced.
const writeRequest = await waitForRequest("terminal.write");
// `terminal.write` and `terminal.resize` declare no success value; the wire
// carries `null`.
succeed(writeRequest.id, null);
const resizeRequest = await waitForRequest("terminal.resize");
succeed(resizeRequest.id, null);

chunk(attachRequest.id, [
  { threadId: THREAD_ID, terminalId: TERMINAL_ID, type: "exited", exitCode: 0, exitSignal: null },
]);

const { outcome } = await running;

await NodeFs.writeFile(
  NodePath.join(out, "shell.json"),
  `${JSON.stringify(
    {
      relayUrl: RELAY,
      httpBaseUrl: HTTP_BASE,
      wsBaseUrl: WS_BASE,
      environmentId: ENVIRONMENT_ID,
      subject: SUBJECT,
      privateJwk: PRIVATE_JWK,
      target: TARGET,
      size: SIZE,
      term: TERM,
      terminalId: TERMINAL_ID,
      threadId: THREAD_ID,
      workspaceCwd: WORKSPACE_CWD,
      socketUrl: sockets[0]?.url ?? null,
      httpCalls,
      clientFrames,
      serverFrames,
      terminalWrites: written,
      outcome,
    },
    null,
    2,
  )}\n`,
);
console.log("shell fixture written to", NodePath.join(out, "shell.json"));
console.log(`  ${httpCalls.length} http calls, ${clientFrames.length} client frames`);
process.exit(0);
