import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import {
  SEED_ALLOWLIST,
  type Frame,
  type HttpStreamOpenFrame,
} from "@heedvane/connector-protocol";

import { AuditLog, type AuditLine } from "./audit-log.js";
import { GitLabHttpStream, type GitLabHttpStreamOptions } from "./gitlab-http-stream.js";

const STREAM_ID = "git-http-test-1";

function waitFor(condition: () => boolean, description: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + 5_000;
    const poll = (): void => {
      if (condition()) return resolve();
      if (Date.now() > deadline) return reject(new Error(`timed out waiting for: ${description}`));
      setTimeout(poll, 10);
    };
    poll();
  });
}

async function stubGitLab(handler: Parameters<typeof createServer>[0]): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  const server: Server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

function openFrame(): HttpStreamOpenFrame {
  return {
    type: "http-stream-open",
    streamId: STREAM_ID,
    method: "POST",
    path: "/acme/widget.git/git-upload-pack",
    query: [],
    headers: { "content-type": "application/x-git-upload-pack-request" },
  };
}

function harness(overrides: Partial<GitLabHttpStreamOptions> = {}) {
  const frames: Frame[] = [];
  const audit: AuditLine[] = [];
  const finalized: string[] = [];
  const stream = new GitLabHttpStream({
    frame: openFrame(),
    entries: SEED_ALLOWLIST,
    profile: "read-only",
    gitlabBaseUrl: "http://127.0.0.1:1",
    gitlabToken: "glpat-local-only",
    timeoutMs: 5_000,
    send: (frame) => frames.push(frame),
    auditLog: new AuditLog((line) => audit.push(line)),
    onFinalized: (streamId) => finalized.push(streamId),
    ...overrides,
  });
  return { stream, frames, audit, finalized };
}

test("Git smart HTTP streams inject the local token and stream bodies in both directions", async () => {
  let authorization = "";
  let requestBody = "";
  const gitlab = await stubGitLab((request, response) => {
    authorization = request.headers.authorization ?? "";
    request.on("data", (chunk: Buffer) => {
      requestBody += chunk.toString("utf8");
    });
    request.on("end", () => {
      response.writeHead(200, { "content-type": "application/x-git-upload-pack-result" });
      response.write("pack-");
      response.end("response");
    });
  });
  try {
    const result = harness({ gitlabBaseUrl: gitlab.baseUrl });
    await result.stream.open();
    result.stream.onData({
      type: "stream-data",
      streamId: STREAM_ID,
      dataBase64: Buffer.from("want-object").toString("base64"),
    });
    result.stream.onClose({ type: "stream-close", streamId: STREAM_ID, reason: "done" });

    await waitFor(
      () => result.frames.some((frame) => frame.type === "stream-close"),
      "GitLab response stream close",
    );
    assert.equal(requestBody, "want-object");
    assert.equal(
      Buffer.from(authorization.slice("Basic ".length), "base64").toString("utf8"),
      "oauth2:glpat-local-only",
    );
    const response = result.frames.find((frame) => frame.type === "http-stream-response");
    assert.equal(response?.type === "http-stream-response" ? response.status : null, 200);
    const body = Buffer.concat(result.frames
      .filter((frame): frame is Extract<Frame, { type: "stream-data" }> => frame.type === "stream-data")
      .map((frame) => Buffer.from(frame.dataBase64, "base64")));
    assert.equal(body.toString("utf8"), "pack-response");
    assert.doesNotMatch(JSON.stringify({ frames: result.frames, audit: result.audit }), /glpat-local-only/);
  } finally {
    await gitlab.close();
  }
});

test("Git smart HTTP streams fail closed when no local credential exists", async () => {
  const result = harness({ gitlabToken: null });
  await result.stream.open();
  const error = result.frames.find((frame) => frame.type === "stream-error");
  assert.equal(error?.type === "stream-error" ? error.code : null, "credential-unavailable");
  assert.deepEqual(result.finalized, [STREAM_ID]);
});
