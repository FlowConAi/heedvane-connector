import assert from "node:assert/strict";
import { execFile, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import {
  encodeFrame,
  SEED_ALLOWLIST,
  SEED_ALLOWLIST_VERSION,
  signAllowlist,
} from "@heedvane/connector-protocol";
import { WebSocketServer } from "ws";

const CONNECTOR_DIR = new URL("..", import.meta.url).pathname;

interface StubServer {
  port: number;
  close: () => Promise<void>;
}

function startHttpStub(handler: (res: import("node:http").ServerResponse) => void): Promise<StubServer> {
  const server: Server = createServer((_req, res) => handler(res));
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
    server.on("error", reject);
  });
}

interface GatewayStub extends StubServer {
  origin: string;
  hellos: Record<string, unknown>[];
}

/** One origin hosting both the WebSocket gateway and the key endpoint, mirroring the
 *  hub deployment the key derivation assumes: GET /connector/allowlist-public-key on
 *  the same host that terminates /connector-gateway. */
function startGatewayStub(input: {
  keys: { publicKey: KeyObject; privateKey: KeyObject };
  keyPem: string | null;
}): Promise<GatewayStub> {
  const signature = signAllowlist(SEED_ALLOWLIST_VERSION, SEED_ALLOWLIST, input.keys.privateKey);
  const hellos: Record<string, unknown>[] = [];
  const httpServer: Server = createServer((req, res) => {
    if (req.url === "/connector/allowlist-public-key" && input.keyPem !== null) {
      res.writeHead(200, { "content-type": "application/x-pem-file" });
      res.end(input.keyPem);
      return;
    }
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"CONNECTOR_ALLOWLIST_PUBLIC_KEY is not configured on this hub."}');
  });
  const wss = new WebSocketServer({ server: httpServer });
  wss.on("connection", (socket) => {
    socket.on("message", (data) => {
      const hello = JSON.parse(data.toString()) as { type?: string };
      if (hello.type !== "client-hello") return;
      hellos.push(hello as Record<string, unknown>);
      socket.send(encodeFrame({
        type: "server-hello",
        connectionId: "conn-boot-test",
        connectorId: "connector-boot-test",
        credential: "cred-boot-test",
        credentialRotatesAt: new Date(Date.now() + 86_400_000).toISOString(),
        allowlistVersion: SEED_ALLOWLIST_VERSION,
        allowlistSignature: signature,
        heartbeatIntervalMs: 30_000,
        minSupportedConnectorVersion: "0.1.0",
      }));
      socket.send(encodeFrame({
        type: "allowlist",
        version: SEED_ALLOWLIST_VERSION,
        signature,
        entries: SEED_ALLOWLIST,
      }));
    });
  });
  return new Promise((resolve, reject) => {
    httpServer.listen(0, "127.0.0.1", () => {
      const { port } = httpServer.address() as AddressInfo;
      resolve({
        port,
        origin: `http://127.0.0.1:${port}`,
        hellos,
        close: () => new Promise((done) => {
          wss.close();
          httpServer.close(() => done());
        }),
      });
    });
    httpServer.on("error", reject);
  });
}

interface BootedCli {
  child: ChildProcess;
  output: () => string;
}

function bootCli(env: Record<string, string>): BootedCli {
  let collected = "";
  const child = execFile(
    process.execPath,
    ["--import", "tsx", "src/cli.ts"],
    { cwd: CONNECTOR_DIR, env: { ...process.env, ...env } },
    (error) => {
      if (error && error.killed === false && error.code !== 0 && error.code !== 1) {
        console.error("[cli.test] unexpected child failure:", error.message, collected);
      }
    },
  );
  child.stdout?.on("data", (chunk: Buffer) => {
    collected += chunk.toString("utf8");
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    collected += chunk.toString("utf8");
  });
  return { child, output: () => collected };
}

function waitForOutput(cli: BootedCli, marker: RegExp): Promise<void> {
  const deadline = Date.now() + 20_000;
  return new Promise((resolve, reject) => {
    const poll = setInterval(() => {
      if (marker.test(cli.output())) {
        clearInterval(poll);
        resolve();
        return;
      }
      if (Date.now() > deadline) {
        clearInterval(poll);
        reject(new Error(`timed out waiting for ${marker}; output was:\n${cli.output()}`));
      }
    }, 50);
  });
}

function waitForExit(child: ChildProcess): Promise<number> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("the CLI did not exit in time")), 20_000);
    child.on("exit", (code) => {
      clearTimeout(timer);
      resolve(code ?? -1);
    });
  });
}

test("boot without HUB_ALLOWLIST_PUBLIC_KEY_FILE fetches the key from the hub and enrolls", async () => {
  const keys = generateKeyPairSync("ed25519");
  const pem = `${keys.publicKey.export({ type: "spki", format: "pem" })}`;
  const gitlab = await startHttpStub((res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"version":"18.11.7-ee"}');
  });
  const gateway = await startGatewayStub({ keys, keyPem: pem });
  const cli = bootCli({
    HEEDVANE_GATEWAY_URL: `ws://127.0.0.1:${gateway.port}/connector-gateway`,
    HEEDVANE_ENROLLMENT_TOKEN: "boot-test-token",
    GITLAB_BASE_URL: `http://127.0.0.1:${gitlab.port}`,
    WEBHOOK_LISTEN_PORT: "18931",
  });
  try {
    await waitForOutput(cli, /verified the signed allowlist/);
    assert.match(cli.output(), new RegExp(`fetching the hub allowlist public key from ${gateway.origin}/connector/allowlist-public-key`));
    assert.match(cli.output(), /tunnel up on connection conn-boot-test/);
    cli.child.kill("SIGTERM");
    assert.equal(await waitForExit(cli.child), 0);
  } finally {
    cli.child.kill("SIGKILL");
    await gitlab.close();
    await gateway.close();
  }
});

test("boot with a token and a MISSING credential file enrolls and persists the issued credential 0600", async () => {
  const keys = generateKeyPairSync("ed25519");
  const pem = `${keys.publicKey.export({ type: "spki", format: "pem" })}`;
  const gitlab = await startHttpStub((res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"version":"18.11.7-ee"}');
  });
  const gateway = await startGatewayStub({ keys, keyPem: pem });
  const stateDir = mkdtempSync(join(tmpdir(), "connector-credential-boot-"));
  const credentialPath = join(stateDir, "credential");
  const cli = bootCli({
    HEEDVANE_GATEWAY_URL: `ws://127.0.0.1:${gateway.port}/connector-gateway`,
    HEEDVANE_ENROLLMENT_TOKEN: "boot-test-token",
    HEEDVANE_CREDENTIAL_FILE: credentialPath,
    GITLAB_BASE_URL: `http://127.0.0.1:${gitlab.port}`,
    WEBHOOK_LISTEN_PORT: "18933",
  });
  try {
    await waitForOutput(cli, /verified the signed allowlist/);
    assert.match(cli.output(), new RegExp(`the long-lived credential is persisted to ${credentialPath.replace(/[/.]/g, "\\$&")}`));
    assert.equal(readFileSync(credentialPath, "utf8").trim(), "cred-boot-test");
    assert.equal(statSync(credentialPath).mode & 0o777, 0o600);
    cli.child.kill("SIGTERM");
    assert.equal(await waitForExit(cli.child), 0);
  } finally {
    cli.child.kill("SIGKILL");
    rmSync(stateDir, { recursive: true, force: true });
    await gitlab.close();
    await gateway.close();
  }
});

test("the systemd env shape survives a restart: boot two resumes with the persisted credential", async () => {
  const keys = generateKeyPairSync("ed25519");
  const pem = `${keys.publicKey.export({ type: "spki", format: "pem" })}`;
  const gitlab = await startHttpStub((res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"version":"18.11.7-ee"}');
  });
  const gateway = await startGatewayStub({ keys, keyPem: pem });
  const stateDir = mkdtempSync(join(tmpdir(), "connector-credential-restart-"));
  const credentialPath = join(stateDir, "credential");
  const env = {
    HEEDVANE_GATEWAY_URL: `ws://127.0.0.1:${gateway.port}/connector-gateway`,
    HEEDVANE_ENROLLMENT_TOKEN: "boot-test-token",
    HEEDVANE_CREDENTIAL_FILE: credentialPath,
    GITLAB_BASE_URL: `http://127.0.0.1:${gitlab.port}`,
    WEBHOOK_LISTEN_PORT: "18934",
  };
  try {
    const first = bootCli(env);
    await waitForOutput(first, /verified the signed allowlist/);
    first.child.kill("SIGTERM");
    assert.equal(await waitForExit(first.child), 0);
    assert.equal(gateway.hellos[0]?.enrollmentToken, "boot-test-token");

    const second = bootCli(env);
    await waitForOutput(second, /verified the signed allowlist/);
    second.child.kill("SIGTERM");
    assert.equal(await waitForExit(second.child), 0);
    // The second boot presents the persisted credential, not the consumed token.
    assert.equal(gateway.hellos[1]?.credential, "cred-boot-test");
    assert.equal(gateway.hellos[1]?.enrollmentToken, undefined);
  } finally {
    rmSync(stateDir, { recursive: true, force: true });
    await gitlab.close();
    await gateway.close();
  }
});

test("a failing key fetch exits 1 with the URL it tried, never silently skipping verification", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startHttpStub((res) => {
    res.writeHead(200);
    res.end("{}");
  });
  const gateway = await startGatewayStub({ keys, keyPem: null });
  const keyUrl = `${gateway.origin}/connector/allowlist-public-key`;
  const cli = bootCli({
    HEEDVANE_GATEWAY_URL: `ws://127.0.0.1:${gateway.port}/connector-gateway`,
    HEEDVANE_ENROLLMENT_TOKEN: "boot-test-token",
    GITLAB_BASE_URL: `http://127.0.0.1:${gitlab.port}`,
    WEBHOOK_LISTEN_PORT: "18932",
  });
  try {
    const exitCode = await waitForExit(cli.child);
    assert.equal(exitCode, 1);
    assert.ok(cli.output().includes(keyUrl), `expected the URL in the error output:\n${cli.output()}`);
    assert.match(cli.output(), /HTTP 404/);
    assert.doesNotMatch(cli.output(), /tunnel up/);
  } finally {
    cli.child.kill("SIGKILL");
    await gitlab.close();
    await gateway.close();
  }
});
