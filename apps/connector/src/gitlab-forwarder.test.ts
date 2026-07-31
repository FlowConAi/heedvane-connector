import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { readFileSync } from "node:fs";
import { createServer as createTlsServer, type Server as TlsServer } from "node:https";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { forwardToGitLab, UpstreamTimeoutError, UpstreamUnreachableError } from "./gitlab-forwarder.js";
import type { GitLabForwardRequest } from "./gitlab-forwarder.js";

interface RecordedCall {
  method: string;
  url: string;
  headers: IncomingMessage["headers"];
  body: Buffer;
}

interface StubGitLab {
  server: Server;
  baseUrl: string;
  calls: RecordedCall[];
  close: () => Promise<void>;
}

const FIXTURES = new URL("./test-fixtures/", import.meta.url);

function startStubGitLab(handler: (call: RecordedCall, res: ServerResponse) => void): Promise<StubGitLab> {
  const calls: RecordedCall[] = [];
  const server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const call: RecordedCall = {
        method: req.method ?? "",
        url: req.url ?? "",
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      calls.push(call);
      handler(call, res);
    });
  });
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        calls,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
    server.on("error", reject);
  });
}

function jsonResponder(call: RecordedCall, res: ServerResponse): void {
  res.writeHead(200, { "content-type": "application/json", "x-gitlab-version": "18.11.7" });
  res.end(JSON.stringify({ echoed: call.url }));
}

function getRequest(overrides: Partial<GitLabForwardRequest> = {}): GitLabForwardRequest {
  return {
    method: "GET",
    path: "/api/v4/version",
    query: [],
    headers: {},
    credential: "glpat-test",
    ...overrides,
  };
}

test("an allowed GET reaches the code host with PRIVATE-TOKEN injected", async () => {
  const stub = await startStubGitLab(jsonResponder);
  try {
    const result = await forwardToGitLab(getRequest(), { baseUrl: stub.baseUrl, timeoutMs: 5_000 });
    assert.equal(result.status, 200);
    assert.equal(stub.calls.length, 1);
    assert.equal(stub.calls[0]?.headers["private-token"], "glpat-test");
    const body = Buffer.from(result.bodyBase64 ?? "", "base64").toString("utf8");
    assert.equal(JSON.parse(body).echoed, "/api/v4/version");
    assert.equal(result.headers["x-gitlab-version"], "18.11.7");
  } finally {
    await stub.close();
  }
});

test("query params travel as repeated encoded pairs, preserving refs[] style names", async () => {
  const stub = await startStubGitLab(jsonResponder);
  try {
    await forwardToGitLab(
      getRequest({
        path: "/api/v4/projects/7/repository/merge_base",
        query: [["refs[]", "main"], ["refs[]", "feature branch"]],
      }),
      { baseUrl: stub.baseUrl, timeoutMs: 5_000 },
    );
    assert.equal(
      stub.calls[0]?.url,
      "/api/v4/projects/7/repository/merge_base?refs%5B%5D=main&refs%5B%5D=feature%20branch",
    );
  } finally {
    await stub.close();
  }
});

test("a POST body is forwarded byte for byte and hop-by-hop headers are rebuilt", async () => {
  const stub = await startStubGitLab(jsonResponder);
  try {
    const raw = Buffer.from([0x00, 0x01, 0x02, 0xff]);
    await forwardToGitLab(
      getRequest({
        method: "POST",
        path: "/api/v4/projects/7/hooks",
        headers: {
          "content-type": "application/octet-stream",
          host: "stale-host.example",
          connection: "keep-alive",
          "content-length": "9999",
          "private-token": "glpat-stale",
        },
        bodyBase64: raw.toString("base64"),
      }),
      { baseUrl: stub.baseUrl, timeoutMs: 5_000 },
    );
    const call = stub.calls[0];
    assert.deepEqual([...call?.body ?? []], [...raw]);
    assert.equal(call?.headers["content-length"], "4");
    assert.equal(call?.headers["private-token"], "glpat-test");
    assert.equal(call?.headers.host, new URL(stub.baseUrl).host);
  } finally {
    await stub.close();
  }
});

test("a refused TCP connection is UpstreamUnreachableError with the real reason", async () => {
  const stub = await startStubGitLab(jsonResponder);
  const { port } = stub.server.address() as AddressInfo;
  await stub.close();
  await assert.rejects(
    forwardToGitLab(getRequest(), { baseUrl: `http://127.0.0.1:${port}`, timeoutMs: 5_000 }),
    (error: unknown) => error instanceof UpstreamUnreachableError && /ECONNREFUSED/.test(error.message),
  );
});

test("a silent code host is UpstreamTimeoutError after the configured budget", async () => {
  const stub = await startStubGitLab(() => {
    // Deliberately never respond: the connector must time out rather than hang.
  });
  try {
    const started = Date.now();
    await assert.rejects(
      forwardToGitLab(getRequest(), { baseUrl: stub.baseUrl, timeoutMs: 150 }),
      (error: unknown) => error instanceof UpstreamTimeoutError && /150/.test(error.message),
    );
    assert.ok(Date.now() - started < 3_000, "the timeout did not actually bound the wait");
  } finally {
    await stub.close();
  }
});

test("an upstream error status passes through with its body, not an exception", async () => {
  const stub = await startStubGitLab((_call, res) => {
    res.writeHead(404, { "content-type": "application/json" });
    res.end('{"message":"404 Project Not Found"}');
  });
  try {
    const result = await forwardToGitLab(getRequest(), { baseUrl: stub.baseUrl, timeoutMs: 5_000 });
    assert.equal(result.status, 404);
    assert.match(Buffer.from(result.bodyBase64 ?? "", "base64").toString("utf8"), /Project Not Found/);
  } finally {
    await stub.close();
  }
});

test("GITLAB_CA_FILE trust lets a self-signed code host verify; without it the failure is truthful", async () => {
  const tlsServer: TlsServer = createTlsServer(
    {
      cert: readFileSync(new URL("localhost-cert.pem", FIXTURES)),
      key: readFileSync(new URL("localhost-key.pem", FIXTURES)),
    },
    (req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(`{"url":"${req.url ?? ""}"}`);
    },
  );
  await new Promise<void>((resolve) => tlsServer.listen(0, "127.0.0.1", resolve));
  const { port } = tlsServer.address() as AddressInfo;
  const baseUrl = `https://localhost:${port}`;
  const ca = readFileSync(new URL("localhost-cert.pem", FIXTURES));
  try {
    const trusted = await forwardToGitLab(getRequest(), { baseUrl, timeoutMs: 5_000, ca });
    assert.equal(trusted.status, 200);
    await assert.rejects(
      forwardToGitLab(getRequest(), { baseUrl, timeoutMs: 5_000 }),
      (error: unknown) => error instanceof UpstreamUnreachableError && /certificate/i.test(error.message),
    );
  } finally {
    await new Promise((done) => tlsServer.close(() => done(null)));
  }
});
