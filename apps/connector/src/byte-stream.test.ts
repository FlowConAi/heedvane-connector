import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { createServer as createTcpServer, type Server, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import {
  DEFAULT_STREAM_WINDOW_BYTES,
  MAX_STREAM_DATA_CHUNK_BYTES,
  type Frame,
  type StreamOpenAckFrame,
} from "@heedvane/connector-protocol";

import { AuditLog, type AuditLine } from "./audit-log.js";
import { GitLabByteStream, type ByteStreamOptions } from "./byte-stream.js";

const CHUNK = MAX_STREAM_DATA_CHUNK_BYTES;
const WINDOW = DEFAULT_STREAM_WINDOW_BYTES;

interface StubGitLab {
  port: number;
  sockets: Socket[];
  received: Buffer[];
  close: () => Promise<void>;
}

function startStubGitLab(onSocket?: (socket: Socket, received: Buffer[]) => void): Promise<StubGitLab> {
  const sockets: Socket[] = [];
  const received: Buffer[] = [];
  const server: Server = createTcpServer((socket) => {
    sockets.push(socket);
    socket.on("data", (chunk: Buffer) => received.push(chunk));
    onSocket?.(socket, received);
  });
  return new Promise((resolve, reject) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = (server.address() as AddressInfo);
      resolve({
        port,
        sockets,
        received,
        close: () => new Promise((done) => {
          for (const socket of sockets) socket.destroy();
          server.close(() => done());
        }),
      });
    });
    server.on("error", reject);
  });
}

interface Harness {
  stream: GitLabByteStream;
  frames: Frame[];
  auditLines: AuditLine[];
  logs: string[];
  finalized: string[];
  sent: () => { data: Frame[]; errors: Frame[]; acks: StreamOpenAckFrame[]; windows: Frame[]; closes: Frame[] };
}

const STREAM_ID = "stream-test-1";
const FRAME_KIND = {
  data: "stream-data",
  error: "stream-error",
  ack: "stream-open-ack",
  window: "stream-window",
  close: "stream-close",
} as const;

function makeStream(overrides: Partial<ByteStreamOptions>): Harness {
  const frames: Frame[] = [];
  const auditLines: AuditLine[] = [];
  const logs: string[] = [];
  const finalized: string[] = [];
  const stream = new GitLabByteStream({
    streamId: STREAM_ID,
    target: { host: "127.0.0.1", port: 1 },
    route: { host: "127.0.0.1", port: 1 },
    identity: null,
    profile: "read-only",
    send: (frame) => frames.push(frame),
    auditLog: new AuditLog((line) => auditLines.push(line)),
    log: (message) => logs.push(message),
    onFinalized: (streamId) => finalized.push(streamId),
    ...overrides,
  });
  return {
    stream,
    frames,
    auditLines,
    logs,
    finalized,
    sent: () => ({
      data: frames.filter((frame) => frame.type === FRAME_KIND.data),
      errors: frames.filter((frame) => frame.type === FRAME_KIND.error),
      acks: frames.filter((frame) => frame.type === FRAME_KIND.ack) as StreamOpenAckFrame[],
      windows: frames.filter((frame) => frame.type === FRAME_KIND.window),
      closes: frames.filter((frame) => frame.type === FRAME_KIND.close),
    }),
  };
}

function dataFrame(payload: string | Buffer): Extract<Frame, { type: "stream-data" }> {
  const buffer = typeof payload === "string" ? Buffer.from(payload) : payload;
  return { type: "stream-data", streamId: STREAM_ID, dataBase64: buffer.toString("base64") };
}

function decodedData(frames: Frame[]): Buffer {
  return Buffer.concat(frames.map((frame) => Buffer.from((frame as { dataBase64: string }).dataBase64, "base64")));
}

async function waitFor(condition: () => boolean, description: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for: ${description}`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function settle(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

test("a target other than the configured GitLab is refused by name without any dial", async () => {
  let dialed = false;
  const harness = makeStream({
    target: { host: "10.0.0.9", port: 443 },
    route: { host: "127.0.0.1", port: 8929 },
    identity: { host: "localhost", port: 18443 },
    dialImpl: (() => {
      dialed = true;
      throw new Error("must not dial");
    }) as unknown as ByteStreamOptions["dialImpl"],
  });
  await harness.stream.open();
  const ack = harness.sent().acks[0];
  assert.equal(ack?.ok, false);
  assert.equal(ack?.code, "target-refused");
  assert.match(ack?.message ?? "", /10\.0\.0\.9:443/);
  assert.match(ack?.message ?? "", /127\.0\.0\.1:8929/);
  assert.match(ack?.message ?? "", /localhost:18443/);
  assert.equal(dialed, false);
  assert.equal(harness.finalized[0], STREAM_ID);
  const audit = harness.auditLines.at(-1);
  assert.equal(audit?.kind, "stream");
  assert.equal(audit?.decision, "refused");
  assert.equal(audit?.target, "10.0.0.9:443");
});

test("the instance IDENTITY authority is accepted, but the dial goes to the route", async () => {
  // Identity (the clone URL the hub registered) and route (the connector's way to the
  // GitLab) differ deliberately: the spec separates identity from route.
  const gitlab = await startStubGitLab((socket, received) => {
    socket.on("data", () => {
      if (Buffer.concat(received).toString() === "ping") socket.write("pong");
    });
  });
  let harness: Harness;
  try {
    harness = makeStream({
      // Nothing listens on the identity address; success proves the dial used the route.
      target: { host: "gitlab-identity.invalid", port: 18443 },
      route: { host: "127.0.0.1", port: gitlab.port },
      identity: { host: "gitlab-identity.invalid", port: 18443 },
    });
    await harness.stream.open();
    await waitFor(() => harness.sent().acks.length === 1, "open ack");
    assert.equal(harness.sent().acks[0]?.ok, true);
    harness.stream.onData(dataFrame("ping"));
    await waitFor(() => decodedData(harness.sent().data).toString() === "pong", "pong through the route");
  } finally {
    harness.stream.destroy("test cleanup");
    await gitlab.close();
  }
});

test("open dials the configured GitLab, acks, and pipes bytes both ways with an audit trail", async () => {
  const PING = "ping";
  const gitlab = await startStubGitLab((socket, received) => {
    socket.on("data", () => {
      if (Buffer.concat(received).toString() === PING) socket.write("pong");
    });
  });
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    await waitFor(() => harness.sent().acks.length === 1, "open ack");
    assert.equal(harness.sent().acks[0]?.ok, true);
    assert.equal(harness.auditLines.at(-1)?.decision, "allowed");

    harness.stream.onData(dataFrame(PING));
    await waitFor(() => Buffer.concat(gitlab.received).toString() === PING, "stub receives ping");
    await waitFor(() => harness.sent().data.length === 1, "pong frame");
    assert.equal(decodedData(harness.sent().data).toString(), "pong");
    // Consumed inbound bytes are topped up for the peer.
    await waitFor(() => harness.sent().windows.length === 1, "window top-up");
    assert.equal((harness.sent().windows[0] as { bytes: number }).bytes, 4);
  } finally {
    harness.stream.destroy("test cleanup");
    await gitlab.close();
  }
});

test("outbound bytes are chunked at the 64 KiB cap", async () => {
  const gitlab = await startStubGitLab((socket) => {
    socket.write(Buffer.alloc(3 * CHUNK, 7));
  });
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    await waitFor(() => decodedData(harness.sent().data).length === 3 * CHUNK, "all chunks forwarded");
    for (const frame of harness.sent().data) {
      const size = Buffer.from((frame as { dataBase64: string }).dataBase64, "base64").length;
      assert.ok(size <= CHUNK, `chunk of ${size} exceeds the cap`);
    }
    // Socket segmentation is not deterministic, so the contract is the cap and the
    // total, never an exact chunk count.
    assert.ok(harness.sent().data.length >= 3);
  } finally {
    harness.stream.destroy("test cleanup");
    await gitlab.close();
  }
});

test("sending stops at the peer window and resumes on stream-window top-ups", async () => {
  const total = WINDOW + 100 * 1024;
  const gitlab = await startStubGitLab((socket) => {
    socket.write(Buffer.alloc(total, 3));
  });
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    await waitFor(() => decodedData(harness.sent().data).length === WINDOW, "initial window fully used");
    await settle(200);
    assert.equal(decodedData(harness.sent().data).length, WINDOW, "no byte sent beyond the advertised window");

    harness.stream.onWindow({ type: "stream-window", streamId: STREAM_ID, bytes: 100 * 1024 });
    await waitFor(() => decodedData(harness.sent().data).length === total, "remainder flows after top-up");
  } finally {
    harness.stream.destroy("test cleanup");
    await gitlab.close();
  }
});

test("a peer exceeding the advertised window is a flow-control-violated stream error", async () => {
  const gitlab = await startStubGitLab();
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    // Five synchronous 64 KiB chunks outrun the flush top-ups: 320 KiB against the 256 KiB window.
    for (let index = 0; index < 5; index += 1) {
      harness.stream.onData(dataFrame(Buffer.alloc(CHUNK, index)));
    }
    await waitFor(() => harness.sent().errors.length === 1, "flow-control error frame");
    const error = harness.sent().errors[0] as { code: string; message: string };
    assert.equal(error.code, "flow-control-violated");
    assert.match(error.message, /window/i);
    assert.equal(harness.finalized[0], STREAM_ID);
    await waitFor(() => gitlab.sockets.every((socket) => socket.destroyed), "socket destroyed");
  } finally {
    await gitlab.close();
  }
});

test("a gateway half-close ends the socket write side while reading continues to remote end", async () => {
  let serverSawFin = false;
  const gitlab = await startStubGitLab((socket) => {
    socket.on("end", () => {
      serverSawFin = true;
      // The read direction still works after the client's FIN.
      socket.write("tail");
      setTimeout(() => socket.end(), 50);
    });
  });
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    harness.stream.onClose({ type: "stream-close", streamId: STREAM_ID, reason: "done" });
    await waitFor(() => serverSawFin, "stub sees FIN on its read side");
    await waitFor(() => decodedData(harness.sent().data).toString() === "tail", "tail still forwarded");
    await waitFor(() => harness.sent().closes.length === 1, "connector closes its side");
    await waitFor(() => harness.finalized.length === 1, "stream finalized once both sides closed");
    const audit = harness.auditLines.at(-1);
    assert.equal(audit?.kind, "stream");
    assert.equal(audit?.bytesOut, 4);
  } finally {
    await gitlab.close();
  }
});

test("a socket reset mid-stream is an upstream-reset error with the real reason", async () => {
  const fakeSocket = new EventEmitter() as Socket;
  fakeSocket.write = ((_chunk: unknown, callback?: () => void) => {
    callback?.();
    return true;
  }) as never;
  fakeSocket.destroy = (() => fakeSocket) as never;
  fakeSocket.end = (() => fakeSocket) as never;
  fakeSocket.pause = (() => fakeSocket) as never;
  fakeSocket.resume = (() => fakeSocket) as never;
  const harness = makeStream({
    target: { host: "127.0.0.1", port: 8929 },
    route: { host: "127.0.0.1", port: 8929 },
    dialImpl: (() => fakeSocket) as unknown as ByteStreamOptions["dialImpl"],
  });
  await harness.stream.open();
  fakeSocket.emit("connect");
  await waitFor(() => harness.sent().acks.length === 1, "open ack");
  fakeSocket.emit("error", new Error("read ECONNRESET"));
  await waitFor(() => harness.sent().errors.length === 1, "reset error frame");
  const error = harness.sent().errors[0] as { code: string; message: string };
  assert.equal(error.code, "upstream-reset");
  assert.match(error.message, /ECONNRESET/);
  assert.equal(harness.finalized[0], STREAM_ID);
});

test("a refused TCP connection is a connect-refused ack with the real reason", async () => {
  const gitlab = await startStubGitLab();
  const { port } = gitlab;
  await gitlab.close();
  const harness = makeStream({
    target: { host: "127.0.0.1", port },
    route: { host: "127.0.0.1", port },
  });
  await harness.stream.open();
  await waitFor(() => harness.sent().acks.length === 1, "connect-refused ack");
  const ack = harness.sent().acks[0];
  assert.equal(ack?.ok, false);
  assert.equal(ack?.code, "connect-refused");
  assert.match(ack?.message ?? "", /ECONNREFUSED/);
  assert.equal(harness.finalized[0], STREAM_ID);
});

test("a connect that never completes is a connect-timeout ack naming the budget", async () => {
  const neverSocket = new EventEmitter() as Socket;
  neverSocket.destroy = () => neverSocket;
  const harness = makeStream({
    target: { host: "10.255.255.1", port: 443 },
    route: { host: "10.255.255.1", port: 443 },
    connectTimeoutMs: 50,
    dialImpl: (() => neverSocket) as unknown as ByteStreamOptions["dialImpl"],
  });
  await harness.stream.open();
  await waitFor(() => harness.sent().acks.length === 1, "connect-timeout ack");
  const ack = harness.sent().acks[0];
  assert.equal(ack?.ok, false);
  assert.equal(ack?.code, "connect-timeout");
  assert.match(ack?.message ?? "", /50ms/);
  assert.equal(harness.finalized[0], STREAM_ID);
});

test("streams die with the tunnel: destroy kills the socket and audits without frames", async () => {
  const gitlab = await startStubGitLab();
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    const framesBefore = harness.frames.length;
    harness.stream.destroy("the tunnel closed");
    assert.equal(harness.finalized[0], STREAM_ID);
    await waitFor(() => gitlab.sockets.every((socket) => socket.destroyed), "socket destroyed");
    assert.equal(harness.frames.length, framesBefore, "no frames are sent into a dead tunnel");
    const audit = harness.auditLines.at(-1);
    assert.equal(audit?.kind, "stream");
    assert.match(audit?.reason ?? "", /tunnel/);
  } finally {
    await gitlab.close();
  }
});

test("stream audit records never carry payload bytes", async () => {
  const gitlab = await startStubGitLab((socket, received) => {
    socket.on("data", () => {
      if (Buffer.concat(received).toString() === "SECRET PAYLOAD") socket.write("SECRET RESPONSE");
    });
  });
  let harness: Harness;
  try {
    harness = makeStream({
      target: { host: "127.0.0.1", port: gitlab.port },
      route: { host: "127.0.0.1", port: gitlab.port },
    });
    await harness.stream.open();
    harness.stream.onData(dataFrame("SECRET PAYLOAD"));
    await waitFor(() => decodedData(harness.sent().data).toString() === "SECRET RESPONSE", "echo");
    harness.stream.destroy("test cleanup");
    const serialized = JSON.stringify(harness.auditLines);
    assert.ok(!serialized.includes("SECRET"), "audit log leaked stream payload bytes");
  } finally {
    await gitlab.close();
  }
});
