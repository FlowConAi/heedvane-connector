import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_STREAM_WINDOW_BYTES,
  FRAME_TYPES,
  CONNECTION_ERROR_CODES,
  FrameValidationError,
  MAX_STREAM_DATA_CHUNK_BYTES,
  MIN_SUPPORTED_CONNECTOR_VERSION,
  PROTOCOL_VERSION,
  STREAM_CLOSE_REASONS,
  STREAM_ERROR_CODES,
  WEBHOOK_VERIFICATION_SCHEMES,
  decodeFrame,
  encodeFrame,
  isRequestFrame,
  isStreamDataFrame,
  isStreamOpenFrame,
  isWebhookFrame,
  type Frame,
  type RequestFrame,
} from "./frames.js";

const ENROLL_HELLO: Frame = {
  type: "client-hello",
  protocolVersion: 1,
  connectorVersion: "0.1.0",
  enrollmentToken: "enroll-single-use",
};

const RESUME_HELLO: Frame = {
  type: "client-hello",
  protocolVersion: 1,
  connectorVersion: "0.1.0-rc.1",
  credential: "connector-long-lived-credential",
};

const ENROLL_SERVER_HELLO: Frame = {
  type: "server-hello",
  connectionId: "conn_1",
  connectorId: "ctr_1",
  credential: "fresh-long-lived-credential",
  credentialRotatesAt: "2026-08-01T00:00:00.000Z",
  allowlistVersion: "1",
  allowlistSignature: "c2ln",
  heartbeatIntervalMs: 30000,
  minSupportedConnectorVersion: "0.1.0",
};

const RESUME_SERVER_HELLO: Frame = {
  type: "server-hello",
  connectionId: "conn_1",
  connectorId: "ctr_1",
  credentialRotatesAt: "2026-08-01T00:00:00.000Z",
  allowlistVersion: "1",
  allowlistSignature: "c2ln",
  heartbeatIntervalMs: 30000,
  minSupportedConnectorVersion: "0.1.0",
};

const ALLOWLIST_FRAME: Frame = {
  type: "allowlist",
  version: "1",
  signature: "c2ln",
  entries: [{ methods: ["GET"], pathPattern: "/api/v4/version", allowedQueryParams: [] }],
};

const REQUEST_WITH_CREDENTIAL: Frame = {
  type: "request",
  streamId: "stream-1",
  requestId: "req-1",
  method: "GET",
  path: "/api/v4/version",
  query: [],
  headers: { accept: "application/json" },
  credential: "code-host-token-held-by-hub",
};

const REQUEST_WITHOUT_CREDENTIAL: Frame = {
  type: "request",
  streamId: "stream-1",
  requestId: "req-2",
  method: "POST",
  path: "/api/v4/projects/42/merge_requests/7/discussions",
  query: [["per_page", "100"]],
  headers: { "content-type": "application/json" },
  bodyBase64: "eyJhIjoxfQ==",
};

const RESPONSE_WITH_BODY: Frame = {
  type: "response",
  streamId: "stream-1",
  requestId: "req-1",
  status: 200,
  headers: { "content-type": "application/json" },
  bodyBase64: "e30=",
};

const RESPONSE_WITHOUT_BODY: Frame = {
  type: "response",
  streamId: "stream-1",
  requestId: "req-3",
  status: 204,
  headers: {},
};

const STREAM_ERROR: Frame = {
  type: "stream-error",
  streamId: "stream-1",
  requestId: "req-2",
  code: "allowlist-refused",
  message: "request shape is outside the connector allowlist",
};

const BYTE_STREAM_ERROR: Frame = {
  type: "stream-error",
  streamId: "bulk-1",
  code: "upstream-reset",
  message: "the connection to the code host broke mid-stream",
};

const STREAM_OPEN: Frame = {
  type: "stream-open",
  streamId: "bulk-1",
  target: { host: "gitlab.customer.example", port: 443 },
};

const STREAM_OPEN_ACK_OK: Frame = { type: "stream-open-ack", streamId: "bulk-1", ok: true };

const STREAM_OPEN_ACK_FAIL: Frame = {
  type: "stream-open-ack",
  streamId: "bulk-1",
  ok: false,
  code: "connect-refused",
  message: "connection refused by 10.0.0.4:443",
};

const HTTP_STREAM_OPEN = {
  type: "http-stream-open",
  streamId: "git-http-1",
  method: "GET",
  path: "/acme/widget.git/info/refs",
  query: [["service", "git-upload-pack"]],
  headers: { accept: "application/x-git-upload-pack-advertisement" },
} as unknown as Frame;

const HTTP_STREAM_RESPONSE = {
  type: "http-stream-response",
  streamId: "git-http-1",
  status: 200,
  headers: { "content-type": "application/x-git-upload-pack-advertisement" },
} as unknown as Frame;

const STREAM_DATA: Frame = { type: "stream-data", streamId: "bulk-1", dataBase64: "AAAA" };

const STREAM_CLOSE: Frame = { type: "stream-close", streamId: "bulk-1", reason: "done" };

const STREAM_CLOSE_NAKED: Frame = { type: "stream-close", streamId: "bulk-1" };

const STREAM_WINDOW: Frame = { type: "stream-window", streamId: "bulk-1", bytes: 65536 };

const WEBHOOK_SECRET_TOKEN: Frame = {
  type: "webhook",
  streamId: "stream-9",
  deliveryId: "delivery-1",
  event: "Merge Request Hook",
  headers: { "x-gitlab-event": "Merge Request Hook", "x-gitlab-token": "shared-secret" },
  bodyBase64: "e30=",
  verificationScheme: "secret-token",
};

const WEBHOOK_SIGNING_TOKEN: Frame = {
  type: "webhook",
  streamId: "stream-9",
  deliveryId: "delivery-2",
  event: "Push Hook",
  headers: { "x-gitlab-event": "Push Hook" },
  bodyBase64: "e30=",
  verificationScheme: "signing-token",
};

const PING: Frame = { type: "ping", nonce: "nonce-1" };
const PONG: Frame = { type: "pong", nonce: "nonce-1" };

const CONNECTION_ERROR: Frame = {
  type: "error",
  code: "connector-version-unsupported",
  message: "connector version 0.0.9 is below the supported floor 0.1.0",
};

const STREAM_ERROR_SAMPLES: readonly Frame[] = STREAM_ERROR_CODES.map((code) => ({
  ...STREAM_ERROR,
  code,
}));

const BYTE_STREAM_ERROR_SAMPLES: readonly Frame[] = STREAM_ERROR_CODES.map((code) => ({
  ...BYTE_STREAM_ERROR,
  code,
}));

const CONNECTION_ERROR_SAMPLES: readonly Frame[] = CONNECTION_ERROR_CODES.map((code) => ({
  ...CONNECTION_ERROR,
  code,
}));

const STREAM_CLOSE_SAMPLES: readonly Frame[] = STREAM_CLOSE_REASONS.map((reason) => ({
  ...STREAM_CLOSE,
  reason,
}));

const SAMPLE_FRAMES: readonly Frame[] = [
  ENROLL_HELLO,
  RESUME_HELLO,
  ENROLL_SERVER_HELLO,
  RESUME_SERVER_HELLO,
  ALLOWLIST_FRAME,
  REQUEST_WITH_CREDENTIAL,
  REQUEST_WITHOUT_CREDENTIAL,
  RESPONSE_WITH_BODY,
  RESPONSE_WITHOUT_BODY,
  ...STREAM_ERROR_SAMPLES,
  ...BYTE_STREAM_ERROR_SAMPLES,
  WEBHOOK_SECRET_TOKEN,
  WEBHOOK_SIGNING_TOKEN,
  STREAM_OPEN,
  STREAM_OPEN_ACK_OK,
  STREAM_OPEN_ACK_FAIL,
  HTTP_STREAM_OPEN,
  HTTP_STREAM_RESPONSE,
  STREAM_DATA,
  ...STREAM_CLOSE_SAMPLES,
  STREAM_CLOSE_NAKED,
  STREAM_WINDOW,
  PING,
  PONG,
  ...CONNECTION_ERROR_SAMPLES,
];

test("every frame type round-trips through encodeFrame/decodeFrame", () => {
  for (const frame of SAMPLE_FRAMES) {
    assert.deepEqual(decodeFrame(encodeFrame(frame)), frame);
  }
});

test("sample set covers every declared frame type", () => {
  // A new frame type without a round-trip sample fails here, so the union cannot grow
  // past its tests silently.
  const covered = new Set(SAMPLE_FRAMES.map((frame) => frame.type));
  assert.deepEqual([...covered].sort(), [...FRAME_TYPES].sort());
});

test("sample set covers every declared closed-union member", () => {
  const streamErrorCodes = SAMPLE_FRAMES
    .filter((frame) => frame.type === "stream-error")
    .map((frame) => frame.code);
  const connectionErrorCodes = SAMPLE_FRAMES
    .filter((frame) => frame.type === "error")
    .map((frame) => frame.code);
  const verificationSchemes = SAMPLE_FRAMES
    .filter((frame) => frame.type === "webhook")
    .map((frame) => frame.verificationScheme);
  const closeReasons = SAMPLE_FRAMES
    .filter((frame) => frame.type === "stream-close")
    .map((frame) => frame.reason)
    .filter((reason) => reason !== undefined);
  assert.deepEqual([...new Set(streamErrorCodes)].sort(), [...STREAM_ERROR_CODES].sort());
  assert.deepEqual([...new Set(connectionErrorCodes)].sort(), [...CONNECTION_ERROR_CODES].sort());
  assert.deepEqual([...new Set(verificationSchemes)].sort(), [...WEBHOOK_VERIFICATION_SCHEMES].sort());
  assert.deepEqual([...new Set(closeReasons)].sort(), [...STREAM_CLOSE_REASONS].sort());
});

test("protocol constants pin version 3, the support floor, and flow-control defaults", () => {
  // Version 3 adds authenticated streaming HTTP. Older peers reject its opening and
  // response frames, so the protocol version remains the capability signal.
  assert.equal(PROTOCOL_VERSION, 3);
  assert.match(MIN_SUPPORTED_CONNECTOR_VERSION, /^\d+\.\d+\.\d+/);
  assert.equal(DEFAULT_STREAM_WINDOW_BYTES, 256 * 1024);
  assert.equal(MAX_STREAM_DATA_CHUNK_BYTES, 64 * 1024);
});

test("authenticated HTTP stream frames carry only request metadata and response metadata", () => {
  const request = decodeFrame(encodeFrame(HTTP_STREAM_OPEN));
  assert.equal(request.type, "http-stream-open");
  assert.equal("credential" in request, false);
  const response = decodeFrame(encodeFrame(HTTP_STREAM_RESPONSE));
  assert.equal(response.type, "http-stream-response");
});

test("client hello carries exactly one of enrollmentToken or credential", () => {
  assertInvalid(
    { type: "client-hello", protocolVersion: 1, connectorVersion: "0.1.0" },
    /enrollmentToken.*credential|credential.*enrollmentToken/,
  );
  assertInvalid(
    {
      type: "client-hello",
      protocolVersion: 1,
      connectorVersion: "0.1.0",
      enrollmentToken: "a",
      credential: "b",
    },
    /enrollmentToken.*credential|credential.*enrollmentToken/,
  );
});

test("request frame carries both credential shapes from day one", () => {
  // Option i: the hub holds the code-host token and sends it on the frame.
  const withCredential = decodeFrame(encodeFrame(REQUEST_WITH_CREDENTIAL)) as RequestFrame;
  assert.equal(withCredential.credential, "code-host-token-held-by-hub");
  // Option ii: the credential stays in the customer network, so the frame omits it and
  // the connector injects it locally. Both shapes must parse.
  const withoutCredential = decodeFrame(encodeFrame(REQUEST_WITHOUT_CREDENTIAL)) as RequestFrame;
  assert.equal(withoutCredential.credential, undefined);
});

test("query params are ordered name/value pairs and survive duplicates", () => {
  const frame: Frame = {
    type: "request",
    streamId: "s",
    requestId: "r",
    method: "GET",
    path: "/api/v4/projects/1/repository/merge_base",
    query: [
      ["refs[]", "base-sha"],
      ["refs[]", "head-sha"],
    ],
    headers: {},
  };
  const parsed = decodeFrame(encodeFrame(frame)) as RequestFrame;
  assert.deepEqual(parsed.query, [
    ["refs[]", "base-sha"],
    ["refs[]", "head-sha"],
  ]);
});

test("server hello omits credential on resume and carries it on enrollment", () => {
  const enrolled = decodeFrame(encodeFrame(ENROLL_SERVER_HELLO));
  assert.ok("credential" in enrolled);
  const resumed = decodeFrame(encodeFrame(RESUME_SERVER_HELLO));
  assert.ok(!("credential" in resumed));
});

test("frame guards narrow by discriminator", () => {
  assert.ok(isRequestFrame(REQUEST_WITH_CREDENTIAL));
  assert.ok(!isRequestFrame(RESPONSE_WITH_BODY));
  assert.ok(isWebhookFrame(WEBHOOK_SECRET_TOKEN));
  assert.ok(!isWebhookFrame(PING));
  assert.ok(!isRequestFrame("a string is not a frame"));
  assert.ok(isStreamOpenFrame(STREAM_OPEN));
  assert.ok(isStreamDataFrame(STREAM_DATA));
  assert.ok(!isStreamOpenFrame(REQUEST_WITH_CREDENTIAL));
  assert.ok(!isStreamDataFrame(STREAM_CLOSE));
});

test("stream-open validates its target", () => {
  assertInvalid({ type: "stream-open", streamId: "s" }, /target/);
  assertInvalid({ type: "stream-open", streamId: "s", target: { host: "", port: 443 } }, /target\.host/);
  assertInvalid({ type: "stream-open", streamId: "s", target: { host: "h", port: 0 } }, /target\.port/);
  assertInvalid({ type: "stream-open", streamId: "s", target: { host: "h", port: 65536 } }, /target\.port/);
  assertInvalid({ type: "stream-open", streamId: "s", target: { host: "h", port: 1.5 } }, /target\.port/);
  assertInvalid({ type: "stream-open", streamId: "s", target: { host: "h", port: "443" } }, /target\.port/);
  assertInvalid({ type: "stream-open", streamId: "", target: { host: "h", port: 443 } }, /streamId/);
});

test("stream-open-ack ties code and message to a failed open", () => {
  assertInvalid({ type: "stream-open-ack", streamId: "s" }, /ok/);
  assertInvalid({ type: "stream-open-ack", streamId: "s", ok: "true" }, /ok/);
  assertInvalid({ type: "stream-open-ack", streamId: "s", ok: true, code: "connect-refused", message: "m" }, /ok is true/);
  assertInvalid({ type: "stream-open-ack", streamId: "s", ok: false, message: "m" }, /code/);
  assertInvalid({ type: "stream-open-ack", streamId: "s", ok: false, code: "connect-refused" }, /message/);
  assertInvalid({ type: "stream-open-ack", streamId: "s", ok: false, code: "nope", message: "m" }, /code/);
});

test("stream-data caps the chunk so bulk cannot monopolize the tunnel", () => {
  // A WebSocket message is the unit the tunnel cannot preempt: one oversized data frame
  // would stall every control frame behind it, so the cap is a shape rule, not a hint.
  const atCap = Buffer.alloc(MAX_STREAM_DATA_CHUNK_BYTES).toString("base64");
  const parsed = decodeFrame(JSON.stringify({ type: "stream-data", streamId: "s", dataBase64: atCap }));
  assert.equal(parsed.type, "stream-data");
  const overCap = Buffer.alloc(MAX_STREAM_DATA_CHUNK_BYTES + 1).toString("base64");
  assertInvalid({ type: "stream-data", streamId: "s", dataBase64: overCap }, /more than/);
  assertInvalid({ type: "stream-data", streamId: "s", dataBase64: "!!" }, /dataBase64/);
  assertInvalid({ type: "stream-data", streamId: "s" }, /dataBase64/);
});

test("stream-window advertises a positive byte credit", () => {
  assertInvalid({ type: "stream-window", streamId: "s", bytes: 0 }, /bytes/);
  assertInvalid({ type: "stream-window", streamId: "s", bytes: -1 }, /bytes/);
  assertInvalid({ type: "stream-window", streamId: "s", bytes: 1.5 }, /bytes/);
  assertInvalid({ type: "stream-window", streamId: "s", bytes: "65536" }, /bytes/);
  const parsed = decodeFrame(JSON.stringify({ type: "stream-window", streamId: "s", bytes: 1 }));
  assert.equal(parsed.type, "stream-window");
});

test("stream-close reason is a closed union and optional", () => {
  assertInvalid({ type: "stream-close", streamId: "s", reason: "nope" }, /reason/);
  assertInvalid({ type: "stream-close", streamId: "s", reason: 7 }, /reason/);
  const naked = decodeFrame(JSON.stringify({ type: "stream-close", streamId: "s" }));
  assert.equal(naked.type, "stream-close");
});

test("stream-error omits requestId on byte streams and keeps it on request streams", () => {
  const byteStream = decodeFrame(encodeFrame(BYTE_STREAM_ERROR));
  assert.ok(!("requestId" in byteStream));
  const requestStream = decodeFrame(encodeFrame(STREAM_ERROR));
  assert.ok("requestId" in requestStream);
  assertInvalid({ type: "stream-error", streamId: "s", requestId: "", code: "upstream-reset", message: "m" }, /requestId/);
});

test("unknown extra fields are tolerated for version skew", () => {
  // Connector and gateway ship independently, so a frame from a newer peer may carry
  // fields this build does not know. Known fields are still fully validated.
  const withFutureField = { ...REQUEST_WITH_CREDENTIAL, futureField: { nested: [1, 2, 3] } };
  const parsed = decodeFrame(JSON.stringify(withFutureField));
  assert.equal(parsed.type, "request");
  assert.ok("futureField" in parsed);
});

test("malformed JSON and non-object frames are rejected", () => {
  assert.throws(() => decodeFrame("{not json"), FrameValidationError);
  assert.throws(() => decodeFrame("42"), FrameValidationError);
  assert.throws(() => decodeFrame("[1,2,3]"), FrameValidationError);
  assert.throws(() => decodeFrame("null"), FrameValidationError);
});

test("unknown frame types are rejected with the type named", () => {
  assert.throws(
    () => decodeFrame(JSON.stringify({ type: "made-up-frame" })),
    /made-up-frame/,
  );
});

test("invalid frames are rejected", () => {
  assertInvalid({ protocolVersion: 1 }, /type/);
  assertInvalid({ type: "client-hello", protocolVersion: 1.5, connectorVersion: "0.1.0", credential: "c" }, /protocolVersion/);
  assertInvalid({ type: "client-hello", protocolVersion: 0, connectorVersion: "0.1.0", credential: "c" }, /protocolVersion/);
  assertInvalid({ type: "client-hello", protocolVersion: 1, connectorVersion: "", credential: "c" }, /connectorVersion/);
  assertInvalid({ type: "client-hello", protocolVersion: 1, connectorVersion: "0.1.0", credential: "" }, /credential/);

  assertInvalid(
    { type: "server-hello", connectionId: "c", connectorId: "k", credentialRotatesAt: "not-a-date", allowlistVersion: "1", allowlistSignature: "c2ln", heartbeatIntervalMs: 1000, minSupportedConnectorVersion: "0.1.0" },
    /credentialRotatesAt/,
  );
  for (const credentialRotatesAt of ["1", "July 29, 2026", "2026-07-29T20:00:00", "2026-02-30T00:00:00Z"]) {
    assertInvalid(
      { type: "server-hello", connectionId: "c", connectorId: "k", credentialRotatesAt, allowlistVersion: "1", allowlistSignature: "c2ln", heartbeatIntervalMs: 1000, minSupportedConnectorVersion: "0.1.0" },
      /credentialRotatesAt/,
    );
  }
  assertInvalid(
    { type: "server-hello", connectionId: "c", connectorId: "k", credentialRotatesAt: "2026-08-01T00:00:00.000Z", allowlistVersion: "1", allowlistSignature: "c2ln", heartbeatIntervalMs: -5, minSupportedConnectorVersion: "0.1.0" },
    /heartbeatIntervalMs/,
  );

  assertInvalid({ type: "allowlist", version: "1", signature: "c2ln", entries: [{ methods: ["TELEPORT"], pathPattern: "/x", allowedQueryParams: [] }] }, /entries/);
  assertInvalid({ type: "allowlist", version: "1", signature: "c2ln", entries: [{ methods: [], pathPattern: "/x", allowedQueryParams: [] }] }, /entries/);

  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "TELEPORT", path: "/api/v4/version", query: [], headers: {} }, /method/);
  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "GET", path: "api/v4/version", query: [], headers: {} }, /path/);
  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "GET", path: "/x", query: [["only-name"]], headers: {} }, /query/);
  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "GET", path: "/x", query: [["a", 1]], headers: {} }, /query/);
  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "GET", path: "/x", query: [], headers: { "x-n": 5 } }, /headers/);
  assertInvalid({ type: "request", streamId: "s", requestId: "r", method: "POST", path: "/x", query: [], headers: {}, bodyBase64: "!!not-base64!!" }, /bodyBase64/);
  assertInvalid({ type: "request", streamId: "", requestId: "r", method: "GET", path: "/x", query: [], headers: {} }, /streamId/);

  assertInvalid({ type: "response", streamId: "s", requestId: "r", status: 99, headers: {} }, /status/);
  assertInvalid({ type: "response", streamId: "s", requestId: "r", status: 600, headers: {} }, /status/);
  assertInvalid({ type: "response", streamId: "s", requestId: "r", status: "200", headers: {} }, /status/);

  assertInvalid({ type: "stream-error", streamId: "s", requestId: "r", code: "nope", message: "m" }, /code/);

  assertInvalid({ type: "webhook", streamId: "s", deliveryId: "d", event: "Push Hook", headers: {}, verificationScheme: "secret-token" }, /bodyBase64/);
  assertInvalid({ type: "webhook", streamId: "s", deliveryId: "d", event: "Push Hook", headers: {}, bodyBase64: "e30=", verificationScheme: "md5" }, /verificationScheme/);

  assertInvalid({ type: "ping" }, /nonce/);
  assertInvalid({ type: "pong", nonce: 7 }, /nonce/);
  assertInvalid({ type: "error", code: "nope", message: "m" }, /code/);
  assertInvalid({ type: "error", code: "frame-invalid", message: "" }, /message/);
});

function assertInvalid(payload: unknown, reason: RegExp): void {
  assert.throws(
    () => decodeFrame(JSON.stringify(payload)),
    (error: unknown) => {
      if (!(error instanceof FrameValidationError)) throw error;
      assert.match(error.message, reason);
      return true;
    },
  );
}
