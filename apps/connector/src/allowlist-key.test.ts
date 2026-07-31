import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { readFileSync } from "node:fs";
import { createServer as createTlsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { createServer as createTcpServer, type Socket, connect as tcpConnect } from "node:net";
import { test } from "node:test";

import { allowlistKeyUrl, AllowlistKeyError, fetchAllowlistPublicKey } from "./allowlist-key.js";

const FIXTURES = new URL("./test-fixtures/", import.meta.url);
const TEST_PEM = `${generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" })}`;

test("the key URL derives http from ws and https from wss with the gateway path swapped", () => {
  assert.equal(
    allowlistKeyUrl("ws://localhost:4000/connector-gateway"),
    "http://localhost:4000/connector/allowlist-public-key",
  );
  assert.equal(
    allowlistKeyUrl("wss://api.heedvane.example/connector-gateway"),
    "https://api.heedvane.example/connector/allowlist-public-key",
  );
  assert.equal(
    allowlistKeyUrl("wss://api.heedvane.example/connector-gateway/"),
    "https://api.heedvane.example/connector/allowlist-public-key",
  );
});

interface KeyServer {
  origin: string;
  close: () => Promise<void>;
}

function startKeyServer(handler: (res: import("node:http").ServerResponse) => void): Promise<KeyServer> {
  const server: Server = createServer((_req, res) => handler(res));
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        origin: `http://127.0.0.1:${port}`,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
    server.on("error", reject);
  });
}

function pemResponder(res: import("node:http").ServerResponse): void {
  res.writeHead(200, { "content-type": "application/x-pem-file" });
  res.end(TEST_PEM);
}

test("a 200 PEM is fetched and parsed into a usable public key", async () => {
  const server = await startKeyServer(pemResponder);
  try {
    const key = await fetchAllowlistPublicKey({
      keyUrl: `${server.origin}/connector/allowlist-public-key`,
      proxyUrl: null,
    });
    assert.equal(key.asymmetricKeyType, "ed25519");
  } finally {
    await server.close();
  }
});

test("a 404 is an honest failure naming the URL it tried", async () => {
  const server = await startKeyServer((res) => {
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"error":"not configured"}');
  });
  try {
    const keyUrl = `${server.origin}/connector/allowlist-public-key`;
    await assert.rejects(
      fetchAllowlistPublicKey({ keyUrl, proxyUrl: null }),
      (error: unknown) =>
        error instanceof AllowlistKeyError && error.message.includes(keyUrl) && /HTTP 404/.test(error.message),
    );
  } finally {
    await server.close();
  }
});

test("a malformed PEM is an honest failure naming the URL it came from", async () => {
  const server = await startKeyServer((res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("this is not a PEM");
  });
  try {
    const keyUrl = `${server.origin}/connector/allowlist-public-key`;
    await assert.rejects(
      fetchAllowlistPublicKey({ keyUrl, proxyUrl: null }),
      (error: unknown) => error instanceof AllowlistKeyError && error.message.includes(keyUrl),
    );
  } finally {
    await server.close();
  }
});

test("an unreachable host is an honest failure naming the URL", async () => {
  const server = await startKeyServer(pemResponder);
  const keyUrl = server.origin;
  await server.close();
  await assert.rejects(
    fetchAllowlistPublicKey({ keyUrl, proxyUrl: null, timeoutMs: 1_000 }),
    (error: unknown) => error instanceof AllowlistKeyError && error.message.includes(keyUrl),
  );
});

test("the fetch rides the configured CONNECT egress proxy", async () => {
  const keyServer = await startKeyServer(pemResponder);
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
  try {
    const key = await fetchAllowlistPublicKey({
      keyUrl: `${keyServer.origin}/connector/allowlist-public-key`,
      proxyUrl: `http://127.0.0.1:${proxyPort}`,
    });
    assert.equal(key.asymmetricKeyType, "ed25519");
    const keyPort = new URL(keyServer.origin).port;
    assert.deepEqual(connectTargets, [`127.0.0.1:${keyPort}`]);
  } finally {
    await keyServer.close();
    await new Promise((done) => proxy.close(() => done(null)));
  }
});

test("a self-signed key host verifies with the gateway CA and fails honestly without it", async () => {
  const tlsServer = createTlsServer(
    {
      cert: readFileSync(new URL("localhost-cert.pem", FIXTURES)),
      key: readFileSync(new URL("localhost-key.pem", FIXTURES)),
    },
    (_req, res) => pemResponder(res),
  );
  await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve));
  const { port } = tlsServer.address() as AddressInfo;
  const keyUrl = `https://localhost:${port}/connector/allowlist-public-key`;
  const ca = readFileSync(new URL("localhost-cert.pem", FIXTURES));
  try {
    const key = await fetchAllowlistPublicKey({ keyUrl, proxyUrl: null, ca });
    assert.equal(key.asymmetricKeyType, "ed25519");
    await assert.rejects(
      fetchAllowlistPublicKey({ keyUrl, proxyUrl: null }),
      (error: unknown) => error instanceof AllowlistKeyError && error.message.includes(keyUrl),
    );
  } finally {
    await new Promise((done) => tlsServer.close(() => done(null)));
  }
});
