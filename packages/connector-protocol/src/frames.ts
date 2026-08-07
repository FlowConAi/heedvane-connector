import {
  HTTP_METHODS,
  isAllowlistEntry,
  isCanonicalRequestPath,
  isHttpMethod,
  type AllowlistEntry,
  type HttpMethod,
} from "./allowlist.js";
import {
  base64DecodedLength,
  isBase64String,
  isIsoTimestamp,
  isNonEmptyString,
  isOneOf,
  isPositiveInteger,
  isQueryParamList,
  isRecord,
  isStringRecord,
} from "./guards.js";

// Version 3 adds authenticated streaming HTTP metadata around the existing flow-
// controlled stream body frames. Older peers reject the new open and response frame
// types, so the version remains the capability signal.
export const PROTOCOL_VERSION = 3;
export const MIN_SUPPORTED_PROTOCOL_VERSION = 2;

// Lowest connector build the gateway will serve. A refusal names both the connector's
// version and this floor; moving the floor is a support-window decision, never a silent
// default.
export const MIN_SUPPORTED_CONNECTOR_VERSION = "0.1.0";

const FRAME_TYPE = {
  clientHello: "client-hello",
  serverHello: "server-hello",
  allowlist: "allowlist",
  request: "request",
  response: "response",
  streamError: "stream-error",
  webhook: "webhook",
  streamOpen: "stream-open",
  streamOpenAck: "stream-open-ack",
  httpStreamOpen: "http-stream-open",
  httpStreamResponse: "http-stream-response",
  streamData: "stream-data",
  streamClose: "stream-close",
  streamWindow: "stream-window",
  ping: "ping",
  pong: "pong",
  error: "error",
} as const;

export const FRAME_TYPES: readonly string[] = Object.values(FRAME_TYPE);

// Query params travel as ordered [name, value] pairs rather than an object, because
// GitLab relies on repeated names (refs[]) and a JSON object cannot carry duplicates.
export type QueryParam = readonly [string, string];

export interface ClientHelloFrame {
  readonly type: "client-hello";
  readonly protocolVersion: number;
  readonly connectorVersion: string;
  readonly enrollmentToken?: string;
  readonly credential?: string;
}

export interface ServerHelloFrame {
  readonly type: "server-hello";
  readonly connectionId: string;
  readonly connectorId: string;
  readonly credential?: string;
  readonly credentialRotatesAt: string;
  readonly allowlistVersion: string;
  readonly allowlistSignature: string;
  readonly heartbeatIntervalMs: number;
  readonly minSupportedConnectorVersion: string;
  /** The instance identity the tunnel serves (the clone URL authority). Optional so peers
   *  predating byte streams stay valid; without it the connector accepts byte streams only
   *  to its configured GitLab route. */
  readonly instanceBaseUrl?: string;
}

export interface AllowlistFrame {
  readonly type: "allowlist";
  readonly version: string;
  readonly signature: string;
  readonly entries: readonly AllowlistEntry[];
}

export interface RequestFrame {
  readonly type: "request";
  readonly streamId: string;
  readonly requestId: string;
  readonly method: HttpMethod;
  readonly path: string;
  readonly query: readonly QueryParam[];
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBase64?: string;
  // Present: the hub holds the code-host token and sends it per request.
  // Absent: the customer connector injects its locally held credential. Both shapes
  // are valid from protocol version 1.
  readonly credential?: string;
}

export interface ResponseFrame {
  readonly type: "response";
  readonly streamId: string;
  readonly requestId: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBase64?: string;
}

export const STREAM_ERROR_CODES = [
  // Request/response stream failures.
  "allowlist-refused",
  "profile-refused",
  "credential-unavailable",
  "upstream-unreachable",
  "upstream-timeout",
  // Raw byte stream failures.
  "target-refused",
  "connect-refused",
  "connect-timeout",
  "upstream-reset",
  "flow-control-violated",
] as const;
export type StreamErrorCode = (typeof STREAM_ERROR_CODES)[number];

// Terminal for its stream: after a stream-error, no further frames carry that streamId.
// requestId is present on request/response streams, where the gateway correlates by it,
// and absent on raw byte streams, which have no requestId to carry.
export interface StreamErrorFrame {
  readonly type: "stream-error";
  readonly streamId: string;
  readonly requestId?: string;
  readonly code: StreamErrorCode;
  readonly message: string;
}

export interface StreamTarget {
  readonly host: string;
  readonly port: number;
}

// Opens a raw bidirectional byte stream to a host inside the customer network. Only the
// gateway opens streams; the connector never does.
export interface StreamOpenFrame {
  readonly type: "stream-open";
  readonly streamId: string;
  readonly target: StreamTarget;
}

// A dedicated ack rather than a second stream-open shape: open carries a target and ack
// carries a result, so one symmetric shape would make every field optional. Failure
// reuses the shared StreamErrorCode set, keeping one vocabulary for stream failures.
export interface StreamOpenAckFrame {
  readonly type: "stream-open-ack";
  readonly streamId: string;
  readonly ok: boolean;
  readonly code?: StreamErrorCode;
  readonly message?: string;
}

/** Opens one allowlisted HTTP exchange whose body travels in stream-data frames. The
 *  connector supplies its local credential; a credential field is deliberately not
 *  part of this frame. */
export interface HttpStreamOpenFrame {
  readonly type: "http-stream-open";
  readonly streamId: string;
  readonly method: HttpMethod;
  readonly path: string;
  readonly query: readonly QueryParam[];
  readonly headers: Readonly<Record<string, string>>;
}

/** Response metadata for an authenticated HTTP stream. Response body bytes follow in
 *  stream-data frames and the directional stream-close ends them. */
export interface HttpStreamResponseFrame {
  readonly type: "http-stream-response";
  readonly streamId: string;
  readonly status: number;
  readonly headers: Readonly<Record<string, string>>;
}

// Initial per-direction send credit for every byte stream, in bytes. A sender must not
// have more unacked bytes in flight than its current credit; the receiver tops credit
// up with stream-window frames as it consumes.
export const DEFAULT_STREAM_WINDOW_BYTES = 256 * 1024;

// Largest payload one stream-data frame may carry, in decoded bytes. A WebSocket
// message is the unit the tunnel cannot preempt, so the chunk cap is what keeps bulk
// clone traffic from stalling webhook and request/response frames queued behind it.
export const MAX_STREAM_DATA_CHUNK_BYTES = 64 * 1024;

export interface StreamDataFrame {
  readonly type: "stream-data";
  readonly streamId: string;
  readonly dataBase64: string;
}

export const STREAM_CLOSE_REASONS = ["done", "reset"] as const;
export type StreamCloseReason = (typeof STREAM_CLOSE_REASONS)[number];

// Directional half-close: the sender will send no more stream-data on this stream. The
// stream is fully closed once both directions have closed; a stream-error ends the
// whole stream immediately.
export interface StreamCloseFrame {
  readonly type: "stream-close";
  readonly streamId: string;
  readonly reason?: StreamCloseReason;
}

// Receiver-advertised flow-control credit: the sender may send this many more bytes on
// the stream. Credits are additive over the lifetime of the stream.
export interface StreamWindowFrame {
  readonly type: "stream-window";
  readonly streamId: string;
  readonly bytes: number;
}

// The connector verifies the exact scheme selected from the authenticated GitLab
// version: classic X-Gitlab-Token for supported 18.x instances, Standard Webhooks
// HMAC for 19+. The hub binds the reported scheme to the stored subscription.
export const WEBHOOK_VERIFICATION_SCHEMES = ["secret-token", "signing-token"] as const;
export type WebhookVerificationScheme = (typeof WEBHOOK_VERIFICATION_SCHEMES)[number];

export interface WebhookFrame {
  readonly type: "webhook";
  readonly streamId: string;
  readonly deliveryId: string;
  readonly event: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBase64: string;
  readonly verificationScheme: WebhookVerificationScheme;
}

export interface PingFrame {
  readonly type: "ping";
  readonly nonce: string;
}

export interface PongFrame {
  readonly type: "pong";
  readonly nonce: string;
}

export const CONNECTION_ERROR_CODES = [
  "enrollment-failed",
  "credential-invalid",
  "protocol-version-unsupported",
  "connector-version-unsupported",
  "frame-invalid",
] as const;
export type ConnectionErrorCode = (typeof CONNECTION_ERROR_CODES)[number];

export interface ErrorFrame {
  readonly type: "error";
  readonly code: ConnectionErrorCode;
  readonly message: string;
}

export type Frame =
  | ClientHelloFrame
  | ServerHelloFrame
  | AllowlistFrame
  | RequestFrame
  | ResponseFrame
  | StreamErrorFrame
  | WebhookFrame
  | StreamOpenFrame
  | StreamOpenAckFrame
  | HttpStreamOpenFrame
  | HttpStreamResponseFrame
  | StreamDataFrame
  | StreamCloseFrame
  | StreamWindowFrame
  | PingFrame
  | PongFrame
  | ErrorFrame;

export class FrameValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FrameValidationError";
  }
}

type FrameFailure = (value: Record<string, unknown>) => string | null;

function clientHelloFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.clientHello) return "type must be client-hello";
  if (!isPositiveInteger(value.protocolVersion)) return "protocolVersion must be a positive integer";
  if (!isNonEmptyString(value.connectorVersion)) return "connectorVersion must be a non-empty string";
  const hasToken = value.enrollmentToken !== undefined;
  const hasCredential = value.credential !== undefined;
  if (hasToken === hasCredential) return "exactly one of enrollmentToken or credential must be present";
  if (hasToken && !isNonEmptyString(value.enrollmentToken)) return "enrollmentToken must be a non-empty string";
  if (hasCredential && !isNonEmptyString(value.credential)) return "credential must be a non-empty string";
  return null;
}

function serverHelloFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.serverHello) return "type must be server-hello";
  if (!isNonEmptyString(value.connectionId)) return "connectionId must be a non-empty string";
  if (!isNonEmptyString(value.connectorId)) return "connectorId must be a non-empty string";
  if (value.credential !== undefined && !isNonEmptyString(value.credential)) {
    return "credential must be a non-empty string when present";
  }
  if (!isIsoTimestamp(value.credentialRotatesAt)) return "credentialRotatesAt must be an ISO 8601 timestamp";
  if (!isNonEmptyString(value.allowlistVersion)) return "allowlistVersion must be a non-empty string";
  if (!isNonEmptyString(value.allowlistSignature)) return "allowlistSignature must be a non-empty string";
  if (!isPositiveInteger(value.heartbeatIntervalMs)) return "heartbeatIntervalMs must be a positive integer";
  if (!isNonEmptyString(value.minSupportedConnectorVersion)) {
    return "minSupportedConnectorVersion must be a non-empty string";
  }
  return null;
}

function allowlistFrameFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.allowlist) return "type must be allowlist";
  if (!isNonEmptyString(value.version)) return "version must be a non-empty string";
  if (!isNonEmptyString(value.signature)) return "signature must be a non-empty string";
  if (!Array.isArray(value.entries) || !value.entries.every(isAllowlistEntry)) {
    return "entries must be valid allowlist entries";
  }
  return null;
}

function requestFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.request) return "type must be request";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isNonEmptyString(value.requestId)) return "requestId must be a non-empty string";
  if (!isHttpMethod(value.method)) return `method must be one of ${HTTP_METHODS.join(", ")}`;
  if (!isNonEmptyString(value.path) || !isCanonicalRequestPath(value.path)) {
    return "path must be an absolute canonical URL path without query, fragment, backslash, or dot segments";
  }
  return requestPayloadFailure(value);
}

function requestPayloadFailure(value: Record<string, unknown>): string | null {
  if (!isQueryParamList(value.query)) return "query must be an array of [name, value] string pairs";
  if (!isStringRecord(value.headers)) return "headers must be a record of string values";
  if (value.bodyBase64 !== undefined && !isBase64String(value.bodyBase64)) return "bodyBase64 must be canonical base64";
  if (value.credential !== undefined && !isNonEmptyString(value.credential)) {
    return "credential must be a non-empty string when present";
  }
  return null;
}

const MIN_HTTP_STATUS = 100;
const MAX_HTTP_STATUS = 599;

function isHttpStatus(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= MIN_HTTP_STATUS && value <= MAX_HTTP_STATUS;
}

function responseFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.response) return "type must be response";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isNonEmptyString(value.requestId)) return "requestId must be a non-empty string";
  if (!isHttpStatus(value.status)) return "status must be an integer between 100 and 599";
  if (!isStringRecord(value.headers)) return "headers must be a record of string values";
  if (value.bodyBase64 !== undefined && !isBase64String(value.bodyBase64)) return "bodyBase64 must be canonical base64";
  return null;
}

function streamErrorFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamError) return "type must be stream-error";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (value.requestId !== undefined && !isNonEmptyString(value.requestId)) {
    return "requestId must be a non-empty string when present";
  }
  if (!isOneOf(value.code, STREAM_ERROR_CODES)) return `code must be one of ${STREAM_ERROR_CODES.join(", ")}`;
  if (!isNonEmptyString(value.message)) return "message must be a non-empty string";
  return null;
}

const MIN_TCP_PORT = 1;
const MAX_TCP_PORT = 65535;

function isTcpPort(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= MIN_TCP_PORT && value <= MAX_TCP_PORT;
}

function streamOpenFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamOpen) return "type must be stream-open";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isRecord(value.target)) return "target must be an object with host and port";
  if (!isNonEmptyString(value.target.host)) return "target.host must be a non-empty string";
  if (!isTcpPort(value.target.port)) return "target.port must be an integer between 1 and 65535";
  return null;
}

function streamOpenAckFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamOpenAck) return "type must be stream-open-ack";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (typeof value.ok !== "boolean") return "ok must be a boolean";
  return streamOpenAckResultFailure(value);
}

function streamOpenAckResultFailure(value: Record<string, unknown>): string | null {
  if (value.ok === true) {
    if (value.code !== undefined || value.message !== undefined) {
      return "code and message must be absent when ok is true";
    }
    return null;
  }
  if (!isOneOf(value.code, STREAM_ERROR_CODES)) return `code must be one of ${STREAM_ERROR_CODES.join(", ")}`;
  if (!isNonEmptyString(value.message)) return "message must be a non-empty string when ok is false";
  return null;
}

function httpStreamOpenFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.httpStreamOpen) return "type must be http-stream-open";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isHttpMethod(value.method)) return `method must be one of ${HTTP_METHODS.join(", ")}`;
  if (!isNonEmptyString(value.path) || !isCanonicalRequestPath(value.path)) {
    return "path must be an absolute canonical URL path without query, fragment, backslash, or dot segments";
  }
  if (!isQueryParamList(value.query)) return "query must be an array of [name, value] string pairs";
  if (!isStringRecord(value.headers)) return "headers must be a record of string values";
  return null;
}

function httpStreamResponseFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.httpStreamResponse) return "type must be http-stream-response";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isHttpStatus(value.status)) return "status must be an integer between 100 and 599";
  if (!isStringRecord(value.headers)) return "headers must be a record of string values";
  return null;
}

function streamDataFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamData) return "type must be stream-data";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isBase64String(value.dataBase64)) return "dataBase64 must be canonical base64";
  if (base64DecodedLength(value.dataBase64) > MAX_STREAM_DATA_CHUNK_BYTES) {
    return `dataBase64 decodes to more than ${MAX_STREAM_DATA_CHUNK_BYTES} bytes`;
  }
  return null;
}

function streamCloseFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamClose) return "type must be stream-close";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (value.reason !== undefined && !isOneOf(value.reason, STREAM_CLOSE_REASONS)) {
    return `reason must be one of ${STREAM_CLOSE_REASONS.join(", ")}`;
  }
  return null;
}

function streamWindowFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.streamWindow) return "type must be stream-window";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isPositiveInteger(value.bytes)) return "bytes must be a positive integer";
  return null;
}

function webhookFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.webhook) return "type must be webhook";
  if (!isNonEmptyString(value.streamId)) return "streamId must be a non-empty string";
  if (!isNonEmptyString(value.deliveryId)) return "deliveryId must be a non-empty string";
  if (!isNonEmptyString(value.event)) return "event must be a non-empty string";
  if (!isStringRecord(value.headers)) return "headers must be a record of string values";
  if (!isBase64String(value.bodyBase64)) return "bodyBase64 must be canonical base64";
  if (!isOneOf(value.verificationScheme, WEBHOOK_VERIFICATION_SCHEMES)) {
    return "verificationScheme must be secret-token or signing-token";
  }
  return null;
}

function pingFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.ping) return "type must be ping";
  if (!isNonEmptyString(value.nonce)) return "nonce must be a non-empty string";
  return null;
}

function pongFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.pong) return "type must be pong";
  if (!isNonEmptyString(value.nonce)) return "nonce must be a non-empty string";
  return null;
}

function errorFailure(value: Record<string, unknown>): string | null {
  if (value.type !== FRAME_TYPE.error) return "type must be error";
  if (!isOneOf(value.code, CONNECTION_ERROR_CODES)) return `code must be one of ${CONNECTION_ERROR_CODES.join(", ")}`;
  if (!isNonEmptyString(value.message)) return "message must be a non-empty string";
  return null;
}

const FRAME_FAILURES: Readonly<Record<string, FrameFailure>> = {
  [FRAME_TYPE.clientHello]: clientHelloFailure,
  [FRAME_TYPE.serverHello]: serverHelloFailure,
  [FRAME_TYPE.allowlist]: allowlistFrameFailure,
  [FRAME_TYPE.request]: requestFailure,
  [FRAME_TYPE.response]: responseFailure,
  [FRAME_TYPE.streamError]: streamErrorFailure,
  [FRAME_TYPE.webhook]: webhookFailure,
  [FRAME_TYPE.streamOpen]: streamOpenFailure,
  [FRAME_TYPE.streamOpenAck]: streamOpenAckFailure,
  [FRAME_TYPE.httpStreamOpen]: httpStreamOpenFailure,
  [FRAME_TYPE.httpStreamResponse]: httpStreamResponseFailure,
  [FRAME_TYPE.streamData]: streamDataFailure,
  [FRAME_TYPE.streamClose]: streamCloseFailure,
  [FRAME_TYPE.streamWindow]: streamWindowFailure,
  [FRAME_TYPE.ping]: pingFailure,
  [FRAME_TYPE.pong]: pongFailure,
  [FRAME_TYPE.error]: errorFailure,
};

export function isClientHelloFrame(value: unknown): value is ClientHelloFrame {
  return isRecord(value) && clientHelloFailure(value) === null;
}

export function isServerHelloFrame(value: unknown): value is ServerHelloFrame {
  return isRecord(value) && serverHelloFailure(value) === null;
}

export function isAllowlistFrame(value: unknown): value is AllowlistFrame {
  return isRecord(value) && allowlistFrameFailure(value) === null;
}

export function isRequestFrame(value: unknown): value is RequestFrame {
  return isRecord(value) && requestFailure(value) === null;
}

export function isResponseFrame(value: unknown): value is ResponseFrame {
  return isRecord(value) && responseFailure(value) === null;
}

export function isStreamErrorFrame(value: unknown): value is StreamErrorFrame {
  return isRecord(value) && streamErrorFailure(value) === null;
}

export function isStreamOpenFrame(value: unknown): value is StreamOpenFrame {
  return isRecord(value) && streamOpenFailure(value) === null;
}

export function isStreamOpenAckFrame(value: unknown): value is StreamOpenAckFrame {
  return isRecord(value) && streamOpenAckFailure(value) === null;
}

export function isHttpStreamOpenFrame(value: unknown): value is HttpStreamOpenFrame {
  return isRecord(value) && httpStreamOpenFailure(value) === null;
}

export function isHttpStreamResponseFrame(value: unknown): value is HttpStreamResponseFrame {
  return isRecord(value) && httpStreamResponseFailure(value) === null;
}

export function isStreamDataFrame(value: unknown): value is StreamDataFrame {
  return isRecord(value) && streamDataFailure(value) === null;
}

export function isStreamCloseFrame(value: unknown): value is StreamCloseFrame {
  return isRecord(value) && streamCloseFailure(value) === null;
}

export function isStreamWindowFrame(value: unknown): value is StreamWindowFrame {
  return isRecord(value) && streamWindowFailure(value) === null;
}

export function isWebhookFrame(value: unknown): value is WebhookFrame {
  return isRecord(value) && webhookFailure(value) === null;
}

export function isPingFrame(value: unknown): value is PingFrame {
  return isRecord(value) && pingFailure(value) === null;
}

export function isPongFrame(value: unknown): value is PongFrame {
  return isRecord(value) && pongFailure(value) === null;
}

export function isErrorFrame(value: unknown): value is ErrorFrame {
  return isRecord(value) && errorFailure(value) === null;
}

// Validators check every known field but never strip unknown ones: connector and
// gateway ship independently, so a frame from a newer peer may carry fields this build
// does not know. Unknown frame types are still rejected.
export function validateFrame(value: unknown): Frame {
  if (!isRecord(value)) throw new FrameValidationError("frame must be a JSON object");
  if (!isNonEmptyString(value.type)) throw new FrameValidationError("frame type must be a non-empty string");
  const failureOf = FRAME_FAILURES[value.type];
  if (!failureOf) throw new FrameValidationError(`unknown frame type "${value.type}"`);
  const failure = failureOf(value);
  if (failure !== null) throw new FrameValidationError(`invalid ${value.type} frame: ${failure}`);
  return value as unknown as Frame;
}

export function encodeFrame(frame: Frame): string {
  return JSON.stringify(frame);
}

export function decodeFrame(payload: string): Frame {
  let parsed: unknown;
  try {
    parsed = JSON.parse(payload);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new FrameValidationError(`frame is not valid JSON: ${reason}`);
  }
  return validateFrame(parsed);
}
