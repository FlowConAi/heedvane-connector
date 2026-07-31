// Per-request policy: a request frame is served only when the signed allowlist matches
// it AND the local capability profile permits the matched entry. Refusals are terminal
// stream-errors with the real reason, and every decision lands in the audit log without
// bodies (the connector is a pipe). Credential injection is the option i / option ii
// split: the frame credential wins (hub-held token), the local GITLAB_TOKEN is the
// fallback (credential stays in the customer network), and neither is a refusal, never
// an unauthenticated upstream call.

import {
  matchesAllowlist,
  pathPatternMatches,
  profilePermits,
  type AllowlistEntry,
  type CapabilityProfile,
  type RequestFrame,
  type ResponseFrame,
  type StreamErrorCode,
  type StreamErrorFrame,
} from "@heedvane/connector-protocol";

import { AUDIT_DECISION, type AuditLog } from "./audit-log.js";
import {
  UpstreamTimeoutError,
  type GitLabForwardRequest,
  type GitLabForwardResult,
} from "./gitlab-forwarder.js";

export interface RequestHandlerDeps {
  readonly entries: readonly AllowlistEntry[];
  readonly profile: CapabilityProfile;
  readonly gitlabToken: string | null;
  readonly forwarder: (request: GitLabForwardRequest) => Promise<GitLabForwardResult>;
  readonly auditLog: AuditLog;
}

const STREAM_ERROR_CODE = {
  allowlistRefused: "allowlist-refused",
  profileRefused: "profile-refused",
  credentialUnavailable: "credential-unavailable",
  upstreamUnreachable: "upstream-unreachable",
  upstreamTimeout: "upstream-timeout",
} as const satisfies Record<string, StreamErrorCode>;

function streamError(frame: RequestFrame, code: StreamErrorCode, message: string): StreamErrorFrame {
  return { type: "stream-error", streamId: frame.streamId, requestId: frame.requestId, code, message };
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function queryParamNames(frame: RequestFrame): string[] {
  return frame.query.map(([name]) => name);
}

interface Refusal {
  readonly frame: RequestFrame;
  readonly deps: RequestHandlerDeps;
  readonly code: StreamErrorCode;
  readonly message: string;
}

function refuse(refusal: Refusal): StreamErrorFrame {
  const { frame, deps, code, message } = refusal;
  deps.auditLog.recordRequest({
    requestId: frame.requestId,
    method: frame.method,
    path: frame.path,
    queryParamNames: queryParamNames(frame),
    decision: AUDIT_DECISION.refused,
    reason: code,
  });
  return streamError(frame, code, message);
}

function unexpectedParamIn(entry: AllowlistEntry, frame: RequestFrame): string | null {
  for (const [name] of frame.query) {
    if (!entry.allowedQueryParams.includes(name)) return name;
  }
  return null;
}

/** matchesAllowlist fails closed without saying which clause failed; for the refusal
 *  message, re-check method and path alone so an operator can tell "unknown endpoint"
 *  apart from "known endpoint, unexpected query parameter". */
function allowlistRefusalMessage(frame: RequestFrame, entries: readonly AllowlistEntry[]): string {
  for (const entry of entries) {
    if (!entry.methods.includes(frame.method) || !pathPatternMatches(entry.pathPattern, frame.path)) continue;
    const param = unexpectedParamIn(entry, frame);
    if (param !== null) {
      return `${frame.method} ${frame.path} carries query parameter "${param}", which the allowlist entry does not permit.`;
    }
  }
  return `${frame.method} ${frame.path} is not in the signed allowlist; the connector does not forward arbitrary requests.`;
}

function resolveCredential(frame: RequestFrame, deps: RequestHandlerDeps): string | null {
  return frame.credential ?? deps.gitlabToken;
}

function upstreamErrorCode(error: unknown): StreamErrorCode {
  return error instanceof UpstreamTimeoutError ? STREAM_ERROR_CODE.upstreamTimeout : STREAM_ERROR_CODE.upstreamUnreachable;
}

async function forwardAndRespond(frame: RequestFrame, deps: RequestHandlerDeps, credential: string): Promise<ResponseFrame | StreamErrorFrame> {
  const started = Date.now();
  try {
    const result = await deps.forwarder({
      method: frame.method,
      path: frame.path,
      query: frame.query,
      headers: frame.headers,
      ...(frame.bodyBase64 !== undefined ? { bodyBase64: frame.bodyBase64 } : {}),
      credential,
    });
    deps.auditLog.recordRequest({
      requestId: frame.requestId,
      method: frame.method,
      path: frame.path,
      queryParamNames: queryParamNames(frame),
      decision: AUDIT_DECISION.allowed,
      reason: "forwarded to the code host",
      upstreamStatus: result.status,
      durationMs: Date.now() - started,
    });
    return {
      type: "response",
      streamId: frame.streamId,
      requestId: frame.requestId,
      status: result.status,
      headers: result.headers,
      ...(result.bodyBase64 !== undefined ? { bodyBase64: result.bodyBase64 } : {}),
    };
  } catch (error) {
    const code = upstreamErrorCode(error);
    return refuse({ frame, deps, code, message: errorMessage(error) });
  }
}

export async function serveRequestFrame(
  frame: RequestFrame,
  deps: RequestHandlerDeps,
): Promise<ResponseFrame | StreamErrorFrame> {
  const entry = matchesAllowlist(deps.entries, { method: frame.method, path: frame.path, query: frame.query });
  if (entry === null) {
    return refuse({
      frame,
      deps,
      code: STREAM_ERROR_CODE.allowlistRefused,
      message: allowlistRefusalMessage(frame, deps.entries),
    });
  }
  if (!profilePermits(deps.profile, entry)) {
    return refuse({
      frame,
      deps,
      code: STREAM_ERROR_CODE.profileRefused,
      message:
        `${frame.method} ${frame.path} is in the signed allowlist but the local capability profile `
          + `"${deps.profile}" refuses it; widen HEEDVANE_CAPABILITY_PROFILE on the connector if this call is intended.`,
    });
  }
  const credential = resolveCredential(frame, deps);
  if (credential === null) {
    return refuse({
      frame,
      deps,
      code: STREAM_ERROR_CODE.credentialUnavailable,
      message:
        "the request carried no credential and the connector has no GITLAB_TOKEN configured; one of the two is required.",
    });
  }
  return await forwardAndRespond(frame, deps, credential);
}
