import assert from "node:assert/strict";
import { test } from "node:test";

import { SEED_ALLOWLIST, type RequestFrame } from "@heedvane/connector-protocol";

import { AuditLog, type AuditLine } from "./audit-log.js";
import {
  UpstreamTimeoutError,
  UpstreamUnreachableError,
  type GitLabForwardRequest,
  type GitLabForwardResult,
} from "./gitlab-forwarder.js";
import { serveRequestFrame, type RequestHandlerDeps } from "./request-handler.js";

const STREAM_ERROR = "stream-error";

function recordingAudit(): { auditLog: AuditLog; lines: AuditLine[] } {
  const lines: AuditLine[] = [];
  return { auditLog: new AuditLog((line) => lines.push(line)), lines };
}

function requestFrame(overrides: Partial<RequestFrame> = {}): RequestFrame {
  return {
    type: "request",
    streamId: "stream-1",
    requestId: "req-1",
    method: "GET",
    path: "/api/v4/version",
    query: [],
    headers: {},
    ...overrides,
  };
}

const UPSTREAM_OK: GitLabForwardResult = {
  status: 200,
  headers: { "content-type": "application/json" },
  bodyBase64: Buffer.from('{"version":"18.11.7"}', "utf8").toString("base64"),
};

function depsWith(overrides: Partial<RequestHandlerDeps>): { deps: RequestHandlerDeps; lines: AuditLine[]; calls: GitLabForwardRequest[] } {
  const { auditLog, lines } = recordingAudit();
  const calls: GitLabForwardRequest[] = [];
  const deps: RequestHandlerDeps = {
    entries: SEED_ALLOWLIST,
    profile: "read-write",
    gitlabToken: null,
    forwarder: (request) => {
      calls.push(request);
      return Promise.resolve(UPSTREAM_OK);
    },
    auditLog,
    ...overrides,
  };
  return { deps, lines, calls };
}

test("option i: the frame credential is injected as the upstream credential", async () => {
  const { deps, calls } = depsWith({ gitlabToken: "glpat-local" });
  const frame = await serveRequestFrame(requestFrame({ credential: "glpat-from-hub" }), deps);
  assert.equal(frame.type, "response");
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.credential, "glpat-from-hub");
});

test("option ii: a credential-absent request falls back to the locally configured token", async () => {
  const { deps, calls } = depsWith({ gitlabToken: "glpat-local" });
  const frame = await serveRequestFrame(requestFrame(), deps);
  assert.equal(frame.type, "response");
  assert.equal(calls[0]?.credential, "glpat-local");
});

test("no credential anywhere is a credential-unavailable stream error, not an upstream call", async () => {
  const { deps, calls, lines } = depsWith({});
  const frame = await serveRequestFrame(requestFrame(), deps);
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "credential-unavailable");
  assert.equal(calls.length, 0);
  assert.equal(lines.at(-1)?.decision, "refused");
});

test("a path outside the signed allowlist is refused without touching the code host", async () => {
  const { deps, calls, lines } = depsWith({});
  const frame = await serveRequestFrame(
    requestFrame({ method: "GET", path: "/api/v4/admin/users", credential: "glpat-from-hub" }),
    deps,
  );
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "allowlist-refused");
  assert.match(frame.message, /GET/);
  assert.match(frame.message, /\/api\/v4\/admin\/users/);
  assert.equal(calls.length, 0);
  const audit = lines.at(-1);
  assert.equal(audit?.decision, "refused");
  assert.equal(audit?.method, "GET");
  assert.equal(audit?.path, "/api/v4/admin/users");
});

test("a query parameter outside the entry's allowed names is refused", async () => {
  const { deps, calls } = depsWith({});
  const frame = await serveRequestFrame(
    requestFrame({ path: "/api/v4/projects", query: [["per_page", "20"], ["admin", "true"]], credential: "tok" }),
    deps,
  );
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "allowlist-refused");
  assert.match(frame.message, /admin/);
  assert.equal(calls.length, 0);
});

test("git-receive-pack is refused even though a write profile is configured", async () => {
  const { deps, calls } = depsWith({});
  const frame = await serveRequestFrame(
    requestFrame({ method: "POST", path: "/group/project.git/git-receive-pack", credential: "tok" }),
    deps,
  );
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "allowlist-refused");
  assert.equal(calls.length, 0);
});

test("the read-only profile refuses a write the allowlist itself permits", async () => {
  const { deps, calls, lines } = depsWith({ profile: "read-only" });
  const frame = await serveRequestFrame(
    requestFrame({ method: "POST", path: "/api/v4/projects/7/hooks", credential: "tok" }),
    deps,
  );
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "profile-refused");
  assert.match(frame.message, /read-only/);
  assert.equal(calls.length, 0);
  assert.equal(lines.at(-1)?.decision, "refused");
});

test("the read-only profile still serves git-upload-pack because clone is a read", async () => {
  const { deps, calls } = depsWith({ profile: "read-only" });
  const frame = await serveRequestFrame(
    requestFrame({ method: "POST", path: "/group/project.git/git-upload-pack", credential: "tok" }),
    deps,
  );
  assert.equal(frame.type, "response");
  assert.equal(calls.length, 1);
});

test("an allowed request maps the upstream result onto a response frame", async () => {
  const { deps, lines } = depsWith({});
  const frame = await serveRequestFrame(requestFrame({ credential: "tok" }), deps);
  assert.equal(frame.type, "response");
  if (frame.type !== "response") return;
  assert.equal(frame.streamId, "stream-1");
  assert.equal(frame.requestId, "req-1");
  assert.equal(frame.status, 200);
  assert.equal(frame.headers["content-type"], "application/json");
  assert.equal(Buffer.from(frame.bodyBase64 ?? "", "base64").toString("utf8"), '{"version":"18.11.7"}');
  const audit = lines.at(-1);
  assert.equal(audit?.decision, "allowed");
  assert.equal(audit?.upstreamStatus, 200);
  assert.equal(typeof audit?.durationMs, "number");
});

test("an upstream timeout maps to upstream-timeout", async () => {
  const { deps } = depsWith({
    forwarder: () => Promise.reject(new UpstreamTimeoutError("timed out after 100ms")),
  });
  const frame = await serveRequestFrame(requestFrame({ credential: "tok" }), deps);
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "upstream-timeout");
  assert.match(frame.message, /100ms/);
});

test("an unreachable code host maps to upstream-unreachable with the real reason", async () => {
  const { deps } = depsWith({
    forwarder: () => Promise.reject(new UpstreamUnreachableError("connect ECONNREFUSED 10.0.0.8:443")),
  });
  const frame = await serveRequestFrame(requestFrame({ credential: "tok" }), deps);
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "upstream-unreachable");
  assert.match(frame.message, /ECONNREFUSED/);
});

test("an unexpected forwarder failure still reports the real error, never a generic one", async () => {
  const { deps } = depsWith({
    forwarder: () => Promise.reject(new Error("socket hang up mid-body")),
  });
  const frame = await serveRequestFrame(requestFrame({ credential: "tok" }), deps);
  assert.equal(frame.type, "stream-error");
  if (frame.type !== STREAM_ERROR) return;
  assert.equal(frame.code, "upstream-unreachable");
  assert.match(frame.message, /socket hang up mid-body/);
});

test("the audit record never carries request or response bodies", async () => {
  const { deps, lines } = depsWith({});
  await serveRequestFrame(
    requestFrame({ credential: "tok", bodyBase64: Buffer.from("SECRET BODY", "utf8").toString("base64") }),
    deps,
  );
  const serialized = JSON.stringify(lines);
  assert.ok(!serialized.includes("SECRET BODY"), "audit log leaked a request body");
  assert.ok(!serialized.includes("18.11.7"), "audit log leaked a response body");
  assert.ok(!serialized.includes('"credential"'), "audit log leaked a credential field");
});
