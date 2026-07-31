import assert from "node:assert/strict";
import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { createServer, type Server } from "node:http";
import { createServer as createTcpServer, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { connect as tcpConnect } from "node:net";
import { test } from "node:test";

import {
  decodeFrame,
  encodeFrame,
  SEED_ALLOWLIST,
  SEED_ALLOWLIST_VERSION,
  signAllowlist,
  type Frame,
  type RequestFrame,
  type WebhookFrame,
} from "@heedvane/connector-protocol";
import { WebSocket, WebSocketServer } from "ws";

import { AuditLog } from "./audit-log.js";
import type { ConnectorConfig } from "./config.js";
import { ConnectorTunnel } from "./tunnel.js";

const FRAME_TYPE = {
  response: "response",
  pong: "pong",
  webhook: "webhook",
  streamData: "stream-data",
  streamOpenAck: "stream-open-ack",
} as const;

const TEST_HEARTBEAT_MS = 30_000;

interface StubGitLab {
  baseUrl: string;
  tokens: (string | undefined)[];
  close: () => Promise<void>;
}

function startStubGitLab(): Promise<StubGitLab> {
  const tokens: (string | undefined)[] = [];
  const server: Server = createServer((req, res) => {
    tokens.push(req.headers["private-token"] as string | undefined);
    res.writeHead(200, { "content-type": "application/json" });
    res.end('{"version":"18.11.7-ee"}');
  });
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        baseUrl: `http://127.0.0.1:${port}`,
        tokens,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
    server.on("error", reject);
  });
}

interface GatewayKeys {
  publicKey: KeyObject;
  privateKey: KeyObject;
}

interface StubGateway {
  url: string;
  hellos: Record<string, unknown>[];
  received: Frame[];
  connectionCount: () => number;
  waitForConnection: () => Promise<WebSocket>;
  close: () => Promise<void>;
}

interface GatewayOptions {
  keys: GatewayKeys;
  credential?: string;
  onHello?: (hello: Record<string, unknown>, socket: WebSocket, gateway: StubGateway) => void;
  onFrame?: (frame: Frame, socket: WebSocket) => void;
}

function helloDefaults(gateway: StubGateway, keys: GatewayKeys, credential?: string): (hello: Record<string, unknown>, socket: WebSocket) => void {
  const signature = signAllowlist(SEED_ALLOWLIST_VERSION, SEED_ALLOWLIST, keys.privateKey);
  return (_hello, socket) => {
    socket.send(encodeFrame({
      type: "server-hello",
      connectionId: "conn-1",
      connectorId: "connector-1",
      ...(credential ? { credential } : {}),
      credentialRotatesAt: new Date(Date.now() + 86_400_000).toISOString(),
      allowlistVersion: SEED_ALLOWLIST_VERSION,
      allowlistSignature: signature,
      heartbeatIntervalMs: TEST_HEARTBEAT_MS,
      minSupportedConnectorVersion: "0.1.0",
      // Extra tolerated field, as the real gateway sends it: the instance identity the
      // byte-stream path accepts alongside the configured GitLab route.
      instanceBaseUrl: "https://gitlab-identity.invalid:18443",
    }));
    socket.send(encodeFrame({
      type: "allowlist",
      version: SEED_ALLOWLIST_VERSION,
      signature,
      entries: SEED_ALLOWLIST,
    }));
    void gateway;
  };
}

function startStubGateway(options: GatewayOptions): Promise<StubGateway> {
  const wss = new WebSocketServer({ port: 0, host: "127.0.0.1" });
  const hellos: Record<string, unknown>[] = [];
  const received: Frame[] = [];
  const sockets: WebSocket[] = [];
  const waiting: ((socket: WebSocket) => void)[] = [];
  const gateway: StubGateway = {
    url: "",
    hellos,
    received,
    connectionCount: () => sockets.length,
    waitForConnection: () => new Promise((resolve) => {
      const existing = sockets.at(-1);
      if (existing) {
        resolve(existing);
        return;
      }
      waiting.push(resolve);
    }),
    close: () => new Promise((done) => {
      for (const socket of sockets) socket.terminate();
      wss.close(() => done(null));
    }),
  };
  const onHello = options.onHello ?? helloDefaults(gateway, options.keys, options.credential);
  wss.on("connection", (socket) => {
    sockets.push(socket);
    for (const resolve of waiting.splice(0)) resolve(socket);
    socket.on("message", (data) => {
      const parsed: unknown = JSON.parse(data.toString());
      if ((parsed as Record<string, unknown>).type === "client-hello") {
        hellos.push(parsed as Record<string, unknown>);
        onHello(parsed as Record<string, unknown>, socket, gateway);
        return;
      }
      const frame = decodeFrame(data.toString());
      received.push(frame);
      options.onFrame?.(frame, socket);
    });
  });
  return new Promise((resolve, reject) => {
    wss.on("listening", () => {
      const { port } = wss.address() as AddressInfo;
      gateway.url = `ws://127.0.0.1:${port}/connector-gateway`;
      resolve(gateway);
    });
    wss.on("error", reject);
  });
}

function testConfig(overrides: Partial<ConnectorConfig>): ConnectorConfig {
  return {
    gatewayUrl: "",
    enrollmentToken: "enroll-token-1",
    credential: null,
    credentialFile: null,
    gitlabBaseUrl: "",
    gitlabToken: null,
    connectorName: "test connector",
    capabilityProfile: "read-write",
    proxyUrl: null,
    gatewayCaFile: null,
    gitlabCaFile: null,
    hubAllowlistPublicKeyFile: "/unused/in/tests.pem",
    webhookListenHost: "127.0.0.1",
    webhookListenPort: 0,
    webhookSecret: null,
    advertiseHost: "connector.internal",
    requestTimeoutMs: 5_000,
    ...overrides,
  };
}

interface TunnelHarness {
  tunnel: ConnectorTunnel;
  issued: string[];
  logs: string[];
  runPromise: Promise<number>;
}

function startTunnel(input: {
  config: ConnectorConfig;
  publicKey: KeyObject;
  webhookListenPort?: number;
}): TunnelHarness {
  const issued: string[] = [];
  const logs: string[] = [];
  const tunnel = new ConnectorTunnel({
    config: input.config,
    allowlistPublicKey: input.publicKey,
    auditLog: new AuditLog(() => undefined),
    log: (message) => logs.push(message),
    onCredentialIssued: (credential) => issued.push(credential),
    webhookBaseUrl: "http://connector.internal:8080/webhooks/gitlab",
    backoff: { baseMs: 25, capMs: 100, jitterRatio: 0 },
    random: () => 1,
  });
  return { tunnel, issued, logs, runPromise: tunnel.run() };
}

async function waitFor(condition: () => boolean, description: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${description}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

function versionRequestFrame(): RequestFrame {
  return {
    type: "request",
    streamId: "stream-gw-1",
    requestId: "req-gw-1",
    method: "GET",
    path: "/api/v4/version",
    query: [],
    headers: {},
    credential: "glpat-hub-held",
  };
}

test("enroll handshake: hello carries token, name, and webhookBaseUrl; the issued credential is persisted", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys, credential: "cred-issued-1" });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => harness.issued.length === 1, "credential issuance");
    assert.equal(harness.issued[0], "cred-issued-1");
    const hello = gateway.hellos[0];
    assert.equal(hello?.enrollmentToken, "enroll-token-1");
    assert.equal(hello?.connectorName, "test connector");
    assert.equal(hello?.webhookBaseUrl, "http://connector.internal:8080/webhooks/gitlab");
    assert.equal(hello?.credential, undefined);
    // No WEBHOOK_SECRET configured: the field stays absent rather than traveling empty.
    assert.equal("webhookSecret" in hello!, false);
  } finally {
    harness.tunnel.stop();
    assert.equal(await harness.runPromise, 0);
    await gateway.close();
    await gitlab.close();
  }
});

test("the hello advertises the configured webhook secret so the hub can provision matching hooks", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys, credential: "cred-issued-1" });
  const harness = startTunnel({
    config: testConfig({
      gatewayUrl: gateway.url,
      gitlabBaseUrl: gitlab.baseUrl,
      webhookSecret: "connector-hook-secret",
    }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => harness.issued.length === 1, "credential issuance");
    assert.equal(gateway.hellos[0]?.webhookSecret, "connector-hook-secret");
  } finally {
    harness.tunnel.stop();
    assert.equal(await harness.runPromise, 0);
    await gateway.close();
    await gitlab.close();
  }
});

test("an allowlisted request frame is served through the tunnel with the frame credential injected", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys, credential: "cred-issued-1" });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  try {
    const socket = await gateway.waitForConnection();
    await waitFor(() => harness.issued.length === 1, "handshake completion");
    socket.send(encodeFrame(versionRequestFrame()));
    await waitFor(() => gateway.received.some((frame) => frame.type === FRAME_TYPE.response), "response frame");
    const response = gateway.received.find((frame) => frame.type === FRAME_TYPE.response);
    assert.equal(response?.type, "response");
    if (response?.type !== FRAME_TYPE.response) return;
    assert.equal(response.streamId, "stream-gw-1");
    assert.equal(response.requestId, "req-gw-1");
    assert.equal(response.status, 200);
    assert.equal(Buffer.from(response.bodyBase64 ?? "", "base64").toString("utf8"), '{"version":"18.11.7-ee"}');
    assert.equal(gitlab.tokens[0], "glpat-hub-held");
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
  }
});

test("a gateway ping is answered with a pong echoing the nonce", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl, credential: "cred-1", enrollmentToken: null }),
    publicKey: keys.publicKey,
  });
  try {
    const socket = await gateway.waitForConnection();
    await waitFor(() => gateway.hellos.length === 1, "hello");
    socket.send(encodeFrame({ type: "ping", nonce: "nonce-abc" }));
    await waitFor(() => gateway.received.some((frame) => frame.type === FRAME_TYPE.pong), "pong");
    const pong = gateway.received.find((frame) => frame.type === FRAME_TYPE.pong);
    assert.equal(pong?.type, "pong");
    if (pong?.type !== FRAME_TYPE.pong) return;
    assert.equal(pong.nonce, "nonce-abc");
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
  }
});

test("a webhook frame is acked by a terminal response on its stream carrying the queue delivery id", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const onFrame = (frame: Frame, socket: WebSocket): void => {
    if (frame.type !== FRAME_TYPE.webhook) return;
    socket.send(encodeFrame({
      type: "response",
      streamId: frame.streamId,
      requestId: frame.deliveryId,
      status: 200,
      headers: { "x-heedvane-delivery-id": "queue-delivery-77" },
    }));
  };
  const gateway = await startStubGateway({ keys, onFrame });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => gateway.hellos.length === 1, "hello");
    const webhook: WebhookFrame = {
      type: "webhook",
      streamId: "stream-hook-1",
      deliveryId: "delivery-local-1",
      event: "Push Hook",
      headers: { "x-gitlab-event": "Push Hook" },
      bodyBase64: Buffer.from("{}").toString("base64"),
      verificationScheme: "secret-token",
    };
    const ack = await harness.tunnel.deliverWebhook(webhook);
    assert.equal(ack.ok, true);
    assert.equal(ack.deliveryId, "queue-delivery-77");
    const sent = gateway.received.find((frame) => frame.type === FRAME_TYPE.webhook);
    assert.equal(sent?.type, "webhook");
    if (sent?.type !== FRAME_TYPE.webhook) return;
    assert.equal(sent.deliveryId, "delivery-local-1");
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
  }
});

test("a hub webhook refusal travels back to the caller with its real status and reason", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const onFrame = (frame: Frame, socket: WebSocket): void => {
    if (frame.type !== FRAME_TYPE.webhook) return;
    socket.send(encodeFrame({
      type: "response",
      streamId: frame.streamId,
      requestId: frame.deliveryId,
      status: 422,
      headers: { "x-heedvane-error": "no webhook subscription matches this connector" },
    }));
  };
  const gateway = await startStubGateway({ keys, onFrame });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => gateway.hellos.length === 1, "hello");
    const ack = await harness.tunnel.deliverWebhook({
      type: "webhook",
      streamId: "stream-hook-2",
      deliveryId: "delivery-local-2",
      event: "Push Hook",
      headers: {},
      bodyBase64: Buffer.from("{}").toString("base64"),
      verificationScheme: "secret-token",
    });
    assert.equal(ack.ok, false);
    assert.equal(ack.status, 422);
    assert.match(ack.error ?? "", /no webhook subscription/);
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
  }
});

test("a webhook delivered while the tunnel is down fails honestly instead of pretending", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const tunnel = new ConnectorTunnel({
    config: testConfig({ gatewayUrl: "ws://127.0.0.1:1/connector-gateway", gitlabBaseUrl: gitlab.baseUrl }),
    allowlistPublicKey: keys.publicKey,
    auditLog: new AuditLog(() => undefined),
    log: () => undefined,
    onCredentialIssued: () => undefined,
    webhookBaseUrl: null,
    backoff: { baseMs: 25, capMs: 100, jitterRatio: 0 },
    random: () => 1,
  });
  const ack = await tunnel.deliverWebhook({
    type: "webhook",
    streamId: "stream-hook-3",
    deliveryId: "delivery-local-3",
    event: "Push Hook",
    headers: {},
    bodyBase64: Buffer.from("{}").toString("base64"),
    verificationScheme: "secret-token",
  });
  assert.equal(ack.ok, false);
  assert.match(ack.error ?? "", /not connected|no live tunnel|tunnel/i);
  await gitlab.close();
});

test("a forged allowlist signature is terminal: nothing is served and the operator log says why", async () => {
  const keys = generateKeyPairSync("ed25519");
  const attackerKeys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys: attackerKeys });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  const exitCode = await harness.runPromise;
  assert.equal(exitCode, 1);
  assert.ok(
    harness.logs.some((line) => /signature/i.test(line)),
    `expected a log line naming the signature failure, got: ${JSON.stringify(harness.logs)}`,
  );
  await gateway.close();
  await gitlab.close();
});

test("a consumed enrollment token exits non-zero with an operator-readable message and no retry storm", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const onHello = (_hello: Record<string, unknown>, socket: WebSocket): void => {
    socket.send(encodeFrame({
      type: "error",
      code: "enrollment-failed",
      message: "the enrollment token is unknown, expired, or already consumed",
    }));
    socket.close(1008, "enrollment-failed");
  };
  const gateway = await startStubGateway({ keys, onHello });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  const exitCode = await harness.runPromise;
  assert.equal(exitCode, 1);
  assert.ok(
    harness.logs.some((line) => /unknown, expired, or already consumed/.test(line)),
    `expected the hub's real refusal in the log, got: ${JSON.stringify(harness.logs)}`,
  );
  await new Promise((resolve) => setTimeout(resolve, 200));
  assert.equal(gateway.connectionCount(), 1, "a terminal refusal must not reconnect");
  await gateway.close();
  await gitlab.close();
});

test("after a drop the tunnel reconnects with the issued credential, not the spent token", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  let handshakes = 0;
  const onHello = (hello: Record<string, unknown>, socket: WebSocket, gateway: StubGateway): void => {
    handshakes += 1;
    helloDefaults(gateway, keys, "cred-issued-1")(hello, socket);
    if (handshakes === 1) setTimeout(() => socket.terminate(), 50);
  };
  const gateway = await startStubGateway({ keys, onHello });
  const harness = startTunnel({
    config: testConfig({ gatewayUrl: gateway.url, gitlabBaseUrl: gitlab.baseUrl }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => gateway.hellos.length >= 2, "reconnect after drop");
    assert.equal(gateway.hellos[0]?.enrollmentToken, "enroll-token-1");
    assert.equal(gateway.hellos[1]?.credential, "cred-issued-1");
    assert.equal(gateway.hellos[1]?.enrollmentToken, undefined);
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
  }
});

test("the tunnel dials out through a corporate CONNECT proxy", async () => {
  const keys = generateKeyPairSync("ed25519");
  const gitlab = await startStubGitLab();
  const gateway = await startStubGateway({ keys });
  const connectTargets: string[] = [];
  const proxy = createTcpServer((clientSide: Socket) => {
    let buffer = Buffer.alloc(0);
    let established = false;
    clientSide.on("data", (chunk: Buffer) => {
      if (established) return;
      buffer = Buffer.concat([buffer, chunk]);
      const headerEnd = buffer.indexOf("\r\n\r\n");
      if (headerEnd === -1) return;
      established = true;
      const requestLine = buffer.subarray(0, headerEnd).toString("utf8").split("\r\n")[0] ?? "";
      const target = requestLine.replace(/^CONNECT\s+/, "").replace(/\s+HTTP.*$/, "");
      connectTargets.push(target);
      const [host, portText] = target.split(":");
      const upstream = tcpConnect(Number(portText), host ?? "127.0.0.1");
      upstream.on("connect", () => {
        clientSide.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        const rest = buffer.subarray(headerEnd + 4);
        if (rest.length > 0) upstream.write(rest);
        clientSide.pipe(upstream);
        upstream.pipe(clientSide);
      });
      upstream.on("error", () => clientSide.destroy());
    });
  });
  await new Promise<void>((resolve) => proxy.listen(0, "127.0.0.1", resolve));
  const proxyPort = (proxy.address() as AddressInfo).port;
  const harness = startTunnel({
    config: testConfig({
      gatewayUrl: gateway.url,
      gitlabBaseUrl: gitlab.baseUrl,
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
    }),
    publicKey: keys.publicKey,
  });
  try {
    await waitFor(() => gateway.hellos.length === 1, "handshake through the proxy");
    const gatewayPort = new URL(gateway.url).port;
    assert.deepEqual(connectTargets, [`127.0.0.1:${gatewayPort}`]);
  } finally {
    harness.tunnel.stop();
    await harness.runPromise;
    await gateway.close();
    await gitlab.close();
    await new Promise((done) => proxy.close(() => done(null)));
  }
});

test("a gateway stream-open to the instance IDENTITY is accepted and dialed via the route, and dies with the tunnel", async () => {
  const keys = generateKeyPairSync("ed25519");
  let echoSocketClosed = false;
  const echoServer = createTcpServer((socket) => {
    socket.on("close", () => {
      echoSocketClosed = true;
    });
    socket.pipe(socket);
  });
  await new Promise<void>((resolve) => echoServer.listen(0, "127.0.0.1", resolve));
  const echoPort = (echoServer.address() as AddressInfo).port;
  const gateway = await startStubGateway({ keys });
  const harness = startTunnel({
    config: testConfig({
      gatewayUrl: gateway.url,
      gitlabBaseUrl: `http://127.0.0.1:${echoPort}`,
      credential: "cred-1",
      enrollmentToken: null,
    }),
    publicKey: keys.publicKey,
  });
  try {
    const socket = await gateway.waitForConnection();
    await waitFor(() => gateway.hellos.length === 1, "hello");
    // The clone URL authority (identity, from the server-hello) differs from the
    // connector's route to the GitLab (GITLAB_BASE_URL, the echo port) on purpose.
    socket.send(encodeFrame({
      type: "stream-open",
      streamId: "stream-e2e-1",
      target: { host: "gitlab-identity.invalid", port: 18443 },
    }));
    await waitFor(
      () => gateway.received.some((frame) => frame.type === FRAME_TYPE.streamOpenAck),
      "stream-open-ack",
    );
    socket.send(encodeFrame({
      type: "stream-data",
      streamId: "stream-e2e-1",
      dataBase64: Buffer.from("clone bytes").toString("base64"),
    }));
    await waitFor(
      () => gateway.received.some((frame) => frame.type === FRAME_TYPE.streamData),
      "echoed stream-data",
    );
    const echoed = gateway.received.find((frame) => frame.type === FRAME_TYPE.streamData);
    assert.equal(
      Buffer.from((echoed as { dataBase64: string }).dataBase64, "base64").toString(),
      "clone bytes",
    );
    // The stream dies with the tunnel: the echo server observes the dial side close.
    socket.terminate();
    await waitFor(() => echoSocketClosed, "stream socket destroyed with the tunnel");
    harness.tunnel.stop();
    await harness.runPromise;
  } finally {
    harness.tunnel.stop();
    await gateway.close();
    await new Promise((done) => echoServer.close(() => done(null)));
  }
});
