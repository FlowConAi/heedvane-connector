// Authenticated, flow-controlled Git smart-HTTP exchange. Unlike the raw protocol-2
// byte stream, this path terminates HTTP at the connector, injects only its local
// GITLAB_TOKEN, and streams request and response bodies without retaining a repository
// pack in memory or sending the credential across the tunnel.

import {
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type RequestOptions,
} from "node:http";
import { request as httpsRequest } from "node:https";

import {
  DEFAULT_STREAM_WINDOW_BYTES,
  MAX_STREAM_DATA_CHUNK_BYTES,
  matchesAllowlist,
  profilePermits,
  type AllowlistEntry,
  type CapabilityProfile,
  type Frame,
  type HttpStreamOpenFrame,
  type StreamCloseFrame,
  type StreamDataFrame,
  type StreamErrorCode,
  type StreamWindowFrame,
} from "@heedvane/connector-protocol";

import { AUDIT_DECISION, type AuditLog } from "./audit-log.js";

const STRIPPED_REQUEST_HEADERS = new Set([
  "authorization",
  "private-token",
  "proxy-authorization",
  "proxy-authenticate",
  "host",
  "connection",
  "transfer-encoding",
  "upgrade",
  "keep-alive",
  "te",
  "trailer",
  "trailers",
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
]);

export interface GitLabHttpStreamOptions {
  readonly frame: HttpStreamOpenFrame;
  readonly entries: readonly AllowlistEntry[];
  readonly profile: CapabilityProfile;
  readonly gitlabBaseUrl: string;
  readonly gitlabToken: string | null;
  readonly timeoutMs: number;
  readonly send: (frame: Frame) => void;
  readonly auditLog: AuditLog;
  readonly onFinalized: (streamId: string) => void;
  readonly ca?: Buffer;
}

function encodedQuery(query: HttpStreamOpenFrame["query"]): string {
  if (query.length === 0) return "";
  return `?${query.map(([name, value]) =>
    `${encodeURIComponent(name)}=${encodeURIComponent(value)}`).join("&")}`;
}

function requestHeaders(frame: HttpStreamOpenFrame, token: string): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(frame.headers)) {
    if (!STRIPPED_REQUEST_HEADERS.has(name.toLowerCase())) headers[name] = value;
  }
  headers.authorization = `Basic ${Buffer.from(`oauth2:${token}`).toString("base64")}`;
  return headers;
}

function responseHeaders(message: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(message.headers)) {
    if (value === undefined || STRIPPED_RESPONSE_HEADERS.has(name.toLowerCase())) continue;
    headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

export class GitLabHttpStream {
  private request: ClientRequest | null = null;
  private response: IncomingMessage | null = null;
  private readonly inboundQueue: Buffer[] = [];
  private readonly outboundQueue: Buffer[] = [];
  private inboundWriting = false;
  private peerInFlight = 0;
  private sendCredit = DEFAULT_STREAM_WINDOW_BYTES;
  private gatewayClosed = false;
  private responseEnded = false;
  private finalized = false;
  private startedAt = Date.now();

  constructor(private readonly options: GitLabHttpStreamOptions) {}

  public async open(): Promise<void> {
    const { frame } = this.options;
    const entry = matchesAllowlist(this.options.entries, {
      method: frame.method,
      path: frame.path,
      query: frame.query,
    });
    if (entry === null) {
      this.refuse("allowlist-refused", `${frame.method} ${frame.path} is not in the signed allowlist.`);
      return;
    }
    if (!profilePermits(this.options.profile, entry)) {
      this.refuse(
        "profile-refused",
        `${frame.method} ${frame.path} is outside the local ${this.options.profile} capability profile.`,
      );
      return;
    }
    if (this.options.gitlabToken === null) {
      this.refuse("credential-unavailable", "GITLAB_TOKEN is required for an authenticated Git HTTP stream.");
      return;
    }
    this.startRequest(this.options.gitlabToken);
  }

  public onData(frame: StreamDataFrame): void {
    if (this.finalized || this.gatewayClosed) return;
    const chunk = Buffer.from(frame.dataBase64, "base64");
    this.peerInFlight += chunk.length;
    if (this.peerInFlight > DEFAULT_STREAM_WINDOW_BYTES) {
      this.fail(
        "flow-control-violated",
        `the gateway exceeded the advertised stream window with ${this.peerInFlight} bytes in flight`,
      );
      return;
    }
    this.inboundQueue.push(chunk);
    this.drainInbound();
  }

  public onWindow(frame: StreamWindowFrame): void {
    if (this.finalized) return;
    this.sendCredit += frame.bytes;
    this.pumpOutbound();
  }

  public onClose(_frame: StreamCloseFrame): void {
    if (this.finalized || this.gatewayClosed) return;
    this.gatewayClosed = true;
    this.drainInbound();
  }

  public destroy(_reason?: string): void {
    if (this.finalized) return;
    this.finalized = true;
    this.request?.destroy();
    this.response?.destroy();
    this.options.onFinalized(this.options.frame.streamId);
  }

  private startRequest(token: string): void {
    const baseUrl = new URL(this.options.gitlabBaseUrl);
    const pathPrefix = baseUrl.pathname === "/" ? "" : baseUrl.pathname.replace(/\/$/, "");
    const requestOptions: RequestOptions = {
      hostname: baseUrl.hostname,
      port: baseUrl.port || (baseUrl.protocol === "https:" ? 443 : 80),
      method: this.options.frame.method,
      path: `${pathPrefix}${this.options.frame.path}${encodedQuery(this.options.frame.query)}`,
      headers: requestHeaders(this.options.frame, token),
      ...(this.options.ca !== undefined ? { ca: this.options.ca } : {}),
    };
    const transport = baseUrl.protocol === "https:" ? httpsRequest : httpRequest;
    const request = transport(requestOptions, (response) => this.onResponse(response));
    this.request = request;
    request.setTimeout(this.options.timeoutMs, () => {
      request.destroy();
      this.fail(
        "upstream-timeout",
        `the code host did not answer ${this.options.frame.method} ${this.options.frame.path} within ${this.options.timeoutMs}ms`,
      );
    });
    request.on("error", (error: Error) => {
      if (!this.finalized) this.fail("upstream-unreachable", `the code host request failed: ${error.message}`);
    });
    this.drainInbound();
  }

  private drainInbound(): void {
    const request = this.request;
    if (request === null || this.inboundWriting || this.finalized) return;
    const chunk = this.inboundQueue.shift();
    if (chunk === undefined) {
      if (this.gatewayClosed && !request.destroyed) request.end();
      return;
    }
    this.inboundWriting = true;
    request.write(chunk, () => {
      this.inboundWriting = false;
      this.peerInFlight -= chunk.length;
      this.emit({ type: "stream-window", streamId: this.options.frame.streamId, bytes: chunk.length });
      this.drainInbound();
    });
  }

  private onResponse(response: IncomingMessage): void {
    if (this.finalized) {
      response.destroy();
      return;
    }
    this.response = response;
    this.emit({
      type: "http-stream-response",
      streamId: this.options.frame.streamId,
      status: response.statusCode ?? 502,
      headers: responseHeaders(response),
    });
    this.options.auditLog.recordRequest({
      requestId: this.options.frame.streamId,
      method: this.options.frame.method,
      path: this.options.frame.path,
      queryParamNames: this.options.frame.query.map(([name]) => name),
      decision: AUDIT_DECISION.allowed,
      reason: "streamed to the code host with the local credential",
      upstreamStatus: response.statusCode ?? 502,
      durationMs: Date.now() - this.startedAt,
    });
    response.on("data", (chunk: Buffer) => {
      for (let offset = 0; offset < chunk.length; offset += MAX_STREAM_DATA_CHUNK_BYTES) {
        this.outboundQueue.push(chunk.subarray(offset, offset + MAX_STREAM_DATA_CHUNK_BYTES));
      }
      this.pumpOutbound();
    });
    response.on("end", () => {
      this.responseEnded = true;
      this.pumpOutbound();
    });
    response.on("error", (error: Error) => {
      if (!this.finalized) this.fail("upstream-reset", `the code host response failed: ${error.message}`);
    });
  }

  private pumpOutbound(): void {
    while (this.outboundQueue.length > 0 && this.sendCredit > 0) {
      const head = this.outboundQueue[0];
      if (head === undefined) break;
      const chunk = head.length <= this.sendCredit ? head : head.subarray(0, this.sendCredit);
      this.sendCredit -= chunk.length;
      if (chunk.length === head.length) this.outboundQueue.shift();
      else this.outboundQueue[0] = head.subarray(chunk.length);
      this.emit({
        type: "stream-data",
        streamId: this.options.frame.streamId,
        dataBase64: chunk.toString("base64"),
      });
    }
    if (this.outboundQueue.length > 0) {
      this.response?.pause();
      return;
    }
    this.response?.resume();
    if (this.responseEnded) {
      this.emit({ type: "stream-close", streamId: this.options.frame.streamId, reason: "done" });
      this.finish();
    }
  }

  private refuse(code: StreamErrorCode, message: string): void {
    this.options.auditLog.recordRequest({
      requestId: this.options.frame.streamId,
      method: this.options.frame.method,
      path: this.options.frame.path,
      queryParamNames: this.options.frame.query.map(([name]) => name),
      decision: AUDIT_DECISION.refused,
      reason: code,
    });
    this.fail(code, message);
  }

  private fail(code: StreamErrorCode, message: string): void {
    if (this.finalized) return;
    this.emit({ type: "stream-error", streamId: this.options.frame.streamId, code, message });
    this.request?.destroy();
    this.response?.destroy();
    this.finish();
  }

  private emit(frame: Frame): void {
    if (!this.finalized) this.options.send(frame);
  }

  private finish(): void {
    if (this.finalized) return;
    this.finalized = true;
    this.options.onFinalized(this.options.frame.streamId);
  }
}
