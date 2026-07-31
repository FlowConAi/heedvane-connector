// The tunnel client: one outbound WebSocket to the connector gateway, framed with
// @heedvane/connector-protocol. Responsibilities, in connect order:
// 1. client-hello with the enrollment token (first boot) or the persisted credential.
// 2. On server-hello with a fresh credential, hand it to the persistence seam.
// 3. Verify the signed allowlist against the embedded hub public key before serving a
//    single request; a bad signature is terminal, never retried into a serve.
// 4. Serve request frames (allowlist plus local capability profile), answer pings with
//    pongs, forward webhook frames and resolve their terminal acks.
// 5. On any drop that is not a terminal refusal, reconnect with capped exponential
//    backoff, resuming with the credential rather than the spent enrollment token.
// Terminal refusals (enrollment failed, credential invalid, version floors, forged
// allowlist) exit non-zero with the peer's real message, because the operator on the
// customer's side cannot inspect the hub to learn why.

import { type KeyObject } from "node:crypto";

import {
  decodeFrame,
  encodeFrame,
  FrameValidationError,
  isAllowlistFrame,
  isErrorFrame,
  isPingFrame,
  isRequestFrame,
  isResponseFrame,
  isServerHelloFrame,
  isStreamCloseFrame,
  isStreamDataFrame,
  isStreamOpenFrame,
  isStreamWindowFrame,
  profilePermits,
  PROTOCOL_VERSION,
  verifySignedAllowlist,
  type AllowlistEntry,
  type AllowlistFrame,
  type ClientHelloFrame,
  type Frame,
  type RequestFrame,
  type ResponseFrame,
  type ServerHelloFrame,
  type StreamCloseFrame,
  type StreamDataFrame,
  type StreamErrorFrame,
  type StreamOpenFrame,
  type StreamWindowFrame,
  type WebhookFrame,
} from "@heedvane/connector-protocol";
import { WebSocket, type ClientOptions } from "ws";

import { type AuditLog } from "./audit-log.js";
import { backoffDelayMs, DEFAULT_BACKOFF, type BackoffOptions } from "./backoff.js";
import { GitLabByteStream, gitLabAuthorityFor } from "./byte-stream.js";
import type { ConnectorConfig } from "./config.js";
import { forwardToGitLab } from "./gitlab-forwarder.js";
import { buildGatewaySocketOptions } from "./proxy-agent.js";
import { serveRequestFrame, type RequestHandlerDeps } from "./request-handler.js";
import { CONNECTOR_VERSION } from "./version.js";
import type { WebhookAck } from "./webhook-listener.js";

export interface ConnectorTunnelOptions {
  readonly config: ConnectorConfig;
  readonly allowlistPublicKey: KeyObject;
  readonly auditLog: AuditLog;
  readonly log: (message: string) => void;
  readonly onCredentialIssued: (credential: string) => void;
  readonly webhookBaseUrl: string | null;
  readonly backoff?: BackoffOptions;
  readonly random?: () => number;
  readonly webhookAckTimeoutMs?: number;
  readonly gatewayCa?: Buffer;
  readonly gitlabCa?: Buffer;
}

const DEFAULT_WEBHOOK_ACK_TIMEOUT_MS = 15_000;
const TUNNEL_DELIVERY_ID_HEADER = "x-heedvane-delivery-id";
const TUNNEL_ERROR_HEADER = "x-heedvane-error";

interface PendingDelivery {
  readonly resolve: (ack: WebhookAck) => void;
  readonly timer: NodeJS.Timeout;
}

interface Session {
  readonly socket: WebSocket;
  hello: ServerHelloFrame | null;
  entries: readonly AllowlistEntry[] | null;
  livenessTimer: NodeJS.Timeout | null;
  /** The instance identity from the server-hello (an extra tolerated field on older
   *  peers): the second authority a byte stream may target. Null when not sent. */
  instanceBaseUrl: string | null;
  /** Open protocol-2 byte streams; they die with this session, never outliving it. */
  streams: Map<string, GitLabByteStream>;
}

type SessionEnd =
  | { readonly kind: "dropped" }
  | { readonly kind: "terminal"; readonly message: string };

/** The three frame types that travel on an already-open byte stream (open has its own
 *  handler). Grouped so onFrame routes them as one branch. */
function isGatewayStreamFrame(frame: Frame): frame is StreamDataFrame | StreamWindowFrame | StreamCloseFrame {
  return isStreamDataFrame(frame) || isStreamWindowFrame(frame) || isStreamCloseFrame(frame);
}

/** server-hello carries instanceBaseUrl as an extension field (protocol validators
 *  tolerate unknown fields, so it arrives intact when the gateway sends it). Shape-
 *  checked here because the declared frame type does not know it. */
function readHelloInstanceBaseUrl(frame: ServerHelloFrame): string | null {
  const value = (frame as unknown as Record<string, unknown>).instanceBaseUrl;
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export class ConnectorTunnel {
  private credential: string | null;
  private session: Session | null = null;
  private readonly pendingDeliveries = new Map<string, PendingDelivery>();
  private stopped = false;
  private sleepTimer: NodeJS.Timeout | null = null;
  private sleepResolve: (() => void) | null = null;
  private lastFrameAt = Date.now();
  private readonly backoff: BackoffOptions;
  private readonly random: () => number;
  private readonly webhookAckTimeoutMs: number;

  constructor(private readonly options: ConnectorTunnelOptions) {
    this.credential = options.config.credential;
    this.backoff = options.backoff ?? DEFAULT_BACKOFF;
    this.random = options.random ?? Math.random;
    this.webhookAckTimeoutMs = options.webhookAckTimeoutMs ?? DEFAULT_WEBHOOK_ACK_TIMEOUT_MS;
  }

  /** Connect and keep the tunnel up until stop() or a terminal refusal. Returns the
   *  process exit code: 0 for a clean stop, 1 for a terminal refusal. */
  public async run(): Promise<number> {
    let attempt = 0;
    while (!this.stopped) {
      const end = await this.runSession();
      if (end.kind === "terminal") {
        this.options.log(`[connector] ${end.message}`);
        return 1;
      }
      if (this.stopped) return 0;
      const delay = backoffDelayMs(attempt, this.backoff, this.random);
      attempt += 1;
      this.options.log(`[connector] the tunnel to the gateway is down; reconnecting in ${delay}ms`);
      await this.sleep(delay);
    }
    return 0;
  }

  public stop(): void {
    this.stopped = true;
    if (this.sleepTimer !== null) clearTimeout(this.sleepTimer);
    this.sleepResolve?.();
    this.failAllPending("the connector is shutting down");
    const socket = this.session?.socket;
    if (socket && socket.readyState === WebSocket.OPEN) socket.close(1000, "connector shutting down");
    if (socket && socket.readyState === WebSocket.CONNECTING) socket.terminate();
    this.clearSession();
  }

  /** Forward a verified local webhook delivery and await the gateway's terminal ack
   *  frame (requestId equals the deliveryId). Never fabricates a success: no live
   *  tunnel is an honest failure, and the hub's refusal travels back verbatim. */
  public async deliverWebhook(frame: WebhookFrame): Promise<WebhookAck> {
    const session = this.session;
    if (!session || session.entries === null || session.socket.readyState !== WebSocket.OPEN) {
      return { ok: false, status: 502, error: "the tunnel to the Heedvane gateway is not connected" };
    }
    const ack = new Promise<WebhookAck>((resolve) => {
      const timer = setTimeout(() => {
        this.pendingDeliveries.delete(frame.deliveryId);
        resolve({
          ok: false,
          status: 504,
          error: `the gateway did not acknowledge delivery ${frame.deliveryId} within ${this.webhookAckTimeoutMs}ms`,
        });
      }, this.webhookAckTimeoutMs);
      timer.unref();
      this.pendingDeliveries.set(frame.deliveryId, { resolve, timer });
    });
    this.send(session, frame);
    return await ack;
  }

  private runSession(): Promise<SessionEnd> {
    const socketOptions: ClientOptions = buildGatewaySocketOptions({
      gatewayUrl: this.options.config.gatewayUrl,
      proxyUrl: this.options.config.proxyUrl,
      ca: this.options.gatewayCa ?? null,
    });
    const socket = new WebSocket(this.options.config.gatewayUrl, socketOptions);
    const session: Session = {
      socket,
      hello: null,
      entries: null,
      livenessTimer: null,
      instanceBaseUrl: null,
      streams: new Map(),
    };
    this.session = session;
    return new Promise<SessionEnd>((resolve) => {
      let finished = false;
      const finish = (end: SessionEnd): void => {
        if (finished) return;
        finished = true;
        this.clearSession();
        resolve(end);
      };
      socket.on("open", () => this.send(session, this.clientHello()));
      socket.on("message", (data: Buffer) => this.onFrame(session, data, finish));
      socket.on("error", (error: Error) => {
        this.options.log(`[connector] gateway socket error: ${error.message}`);
      });
      socket.on("close", (code: number, reason: Buffer) => {
        const detail = reason.length > 0 ? ` (${code}: ${reason.toString("utf8")})` : ` (code ${code})`;
        this.options.log(`[connector] the gateway closed the tunnel${detail}`);
        this.failAllPending("the tunnel closed while the delivery was in flight");
        finish({ kind: "dropped" });
      });
    });
  }

  private clientHello(): ClientHelloFrame {
    const auth = this.helloAuth();
    return {
      type: "client-hello",
      protocolVersion: PROTOCOL_VERSION,
      connectorVersion: CONNECTOR_VERSION,
      ...auth,
      ...(this.options.config.connectorName ? { connectorName: this.options.config.connectorName } : {}),
      ...(this.options.webhookBaseUrl ? { webhookBaseUrl: this.options.webhookBaseUrl } : {}),
      // The webhook secret travels so the hub can provision hooks whose token matches
      // what this connector verifies locally; absent when WEBHOOK_SECRET is not set.
      ...(this.options.config.webhookSecret ? { webhookSecret: this.options.config.webhookSecret } : {}),
    };
  }

  private helloAuth(): { credential: string } | { enrollmentToken: string } {
    if (this.credential !== null) return { credential: this.credential };
    const token = this.options.config.enrollmentToken;
    if (token === null) {
      throw new Error("the connector has neither a credential nor an enrollment token; configuration guarantees one");
    }
    return { enrollmentToken: token };
  }

  private onFrame(session: Session, data: Buffer, finish: (end: SessionEnd) => void): void {
    let frame: Frame;
    try {
      frame = decodeFrame(data.toString("utf8"));
    } catch (error) {
      this.options.log(
        `[connector] dropping the tunnel: the gateway sent an invalid frame: `
          + `${error instanceof FrameValidationError ? error.message : errorMessage(error)}`,
      );
      session.socket.terminate();
      finish({ kind: "dropped" });
      return;
    }
    this.lastFrameAt = Date.now();
    if (isServerHelloFrame(frame)) return this.onServerHello(session, frame);
    if (isAllowlistFrame(frame)) return this.onAllowlist(session, frame, finish);
    if (isRequestFrame(frame)) return this.onRequest(session, frame, finish);
    if (isStreamOpenFrame(frame)) return this.onStreamOpen(session, frame, finish);
    if (isGatewayStreamFrame(frame)) return this.onStreamFrame(session, frame);
    if (isPingFrame(frame)) return this.send(session, { type: "pong", nonce: frame.nonce });
    if (isResponseFrame(frame)) return this.onWebhookAck(frame);
    if (isErrorFrame(frame)) {
      finish({ kind: "terminal", message: `the gateway refused the tunnel: ${frame.code}: ${frame.message}` });
      session.socket.close(1008, frame.code);
      return;
    }
    // client-hello, pong, stream-error, stream-open-ack, and webhook travel
    // connector-to-gateway; a gateway sending any of them is confused or forged, so
    // the tunnel fails closed.
    this.options.log(`[connector] dropping the tunnel: a gateway must not send ${frame.type} frames`);
    session.socket.terminate();
    finish({ kind: "dropped" });
  }

  /** Open a protocol-2 byte stream. The same readiness gate as request frames applies:
   *  a gateway that opens streams before delivering the signed allowlist is confused. */
  private onStreamOpen(session: Session, frame: StreamOpenFrame, finish: (end: SessionEnd) => void): void {
    if (session.entries === null) {
      this.options.log(
        `[connector] dropping the tunnel: stream-open ${frame.streamId} arrived before the signed allowlist`,
      );
      session.socket.terminate();
      finish({ kind: "dropped" });
      return;
    }
    const config = this.options.config;
    const stream = new GitLabByteStream({
      streamId: frame.streamId,
      target: frame.target,
      route: gitLabAuthorityFor(config.gitlabBaseUrl),
      identity: session.instanceBaseUrl !== null ? gitLabAuthorityFor(session.instanceBaseUrl) : null,
      profile: config.capabilityProfile,
      send: (outbound) => this.send(session, outbound),
      auditLog: this.options.auditLog,
      log: this.options.log,
      onFinalized: (streamId) => session.streams.delete(streamId),
    });
    session.streams.set(frame.streamId, stream);
    void stream.open().then(undefined, (error: unknown) => {
      // open() handles refusal and dial failures itself; a throw here is a connector
      // bug, so the stream dies with a truthful error rather than hanging.
      this.options.log(`[connector] stream ${frame.streamId} failed to open: ${errorMessage(error)}`);
      stream.destroy(`open failure: ${errorMessage(error)}`);
    });
  }

  private onStreamFrame(session: Session, frame: StreamDataFrame | StreamWindowFrame | StreamCloseFrame): void {
    const stream = session.streams.get(frame.streamId);
    if (!stream) {
      this.options.log(
        `[connector] ignoring a ${frame.type} frame for unknown stream ${frame.streamId}; `
          + "the stream is closed or never existed here",
      );
      return;
    }
    if (isStreamDataFrame(frame)) return stream.onData(frame);
    if (isStreamWindowFrame(frame)) return stream.onWindow(frame);
    stream.onClose(frame);
  }

  private onServerHello(session: Session, frame: ServerHelloFrame): void {
    if (session.hello !== null) {
      this.options.log("[connector] ignoring a duplicate server-hello on an established tunnel");
      return;
    }
    session.hello = frame;
    session.instanceBaseUrl = readHelloInstanceBaseUrl(frame);
    if (frame.credential !== undefined) {
      this.credential = frame.credential;
      this.options.onCredentialIssued(frame.credential);
    }
    this.armLiveness(session, frame.heartbeatIntervalMs);
    this.options.log(
      `[connector] tunnel up on connection ${frame.connectionId} (connector ${frame.connectorId}, `
        + `protocol ${PROTOCOL_VERSION}, heartbeat ${frame.heartbeatIntervalMs}ms, `
        + `credential rotates at ${frame.credentialRotatesAt})`,
    );
  }

  private onAllowlist(session: Session, frame: AllowlistFrame, finish: (end: SessionEnd) => void): void {
    try {
      const verified = verifySignedAllowlist(
        { version: frame.version, signature: frame.signature, entries: frame.entries },
        this.options.allowlistPublicKey,
      );
      this.checkAnnouncement(session, frame.version, frame.signature);
      session.entries = verified.entries;
      const outside = verified.entries.filter((entry) => !profilePermits(this.options.config.capabilityProfile, entry));
      this.options.log(
        `[connector] verified the signed allowlist v${verified.version}: ${verified.entries.length} entries, `
          + `${outside.length} outside the local "${this.options.config.capabilityProfile}" capability profile `
          + "(refused at request time)",
      );
    } catch (error) {
      finish({
        kind: "terminal",
        message: `the gateway's signed allowlist failed verification: ${errorMessage(error)}. `
          + "Check HUB_ALLOWLIST_PUBLIC_KEY_FILE against the hub's published allowlist public key.",
      });
      session.socket.close(1008, "allowlist-invalid");
      return;
    }
  }

  /** server-hello announces the allowlist before the document arrives; a mismatch is a
   *  confused or forged peer, so it fails closed like a bad signature. */
  private checkAnnouncement(session: Session, version: string, signature: string): void {
    if (session.hello === null) throw new Error("the allowlist frame arrived before the server-hello");
    if (session.hello.allowlistVersion !== version || session.hello.allowlistSignature !== signature) {
      throw new Error("the allowlist document does not match the server-hello announcement");
    }
  }

  private onRequest(session: Session, frame: RequestFrame, finish: (end: SessionEnd) => void): void {
    if (session.entries === null) {
      this.options.log(
        `[connector] dropping the tunnel: request ${frame.requestId} arrived before the signed allowlist`,
      );
      session.socket.terminate();
      finish({ kind: "dropped" });
      return;
    }
    void serveRequestFrame(frame, this.requestHandlerDeps(session.entries)).then((result) => {
      this.send(session, result);
    }, (error: unknown) => {
      // A handler failure here is a connector bug, not an upstream condition: fail the
      // stream truthfully rather than letting the gateway time the request out.
      const failure: StreamErrorFrame = {
        type: "stream-error",
        streamId: frame.streamId,
        requestId: frame.requestId,
        code: "upstream-unreachable",
        message: `the connector failed while serving the request: ${errorMessage(error)}`,
      };
      this.send(session, failure);
    });
  }

  private requestHandlerDeps(entries: readonly AllowlistEntry[]): RequestHandlerDeps {
    const config = this.options.config;
    return {
      entries,
      profile: config.capabilityProfile,
      gitlabToken: config.gitlabToken,
      forwarder: (request) => forwardToGitLab(request, {
        baseUrl: config.gitlabBaseUrl,
        timeoutMs: config.requestTimeoutMs,
        ...(this.options.gitlabCa !== undefined ? { ca: this.options.gitlabCa } : {}),
      }),
      auditLog: this.options.auditLog,
    };
  }

  private onWebhookAck(frame: ResponseFrame): void {
    const pending = this.pendingDeliveries.get(frame.requestId);
    if (!pending) {
      this.options.log(
        `[connector] ignoring a response frame for unknown stream ${frame.requestId}; `
          + "no pending webhook delivery carries that id",
      );
      return;
    }
    clearTimeout(pending.timer);
    this.pendingDeliveries.delete(frame.requestId);
    if (frame.status === 200) {
      pending.resolve({
        ok: true,
        status: 200,
        deliveryId: frame.headers[TUNNEL_DELIVERY_ID_HEADER] ?? "unknown",
      });
      return;
    }
    pending.resolve({
      ok: false,
      status: frame.status,
      error: frame.headers[TUNNEL_ERROR_HEADER] ?? `the hub answered HTTP ${frame.status}`,
    });
  }

  private armLiveness(session: Session, heartbeatIntervalMs: number): void {
    if (session.livenessTimer !== null) clearInterval(session.livenessTimer);
    const limit = heartbeatIntervalMs * 2;
    session.livenessTimer = setInterval(() => {
      const idleMs = Date.now() - this.lastFrameAt;
      if (idleMs <= limit) return;
      this.options.log(
        `[connector] no frame from the gateway in ${idleMs}ms (heartbeat interval ${heartbeatIntervalMs}ms); `
          + "cycling the tunnel",
      );
      session.socket.terminate();
    }, heartbeatIntervalMs);
    session.livenessTimer.unref();
  }

  private failAllPending(reason: string): void {
    for (const [deliveryId, pending] of this.pendingDeliveries) {
      clearTimeout(pending.timer);
      pending.resolve({ ok: false, status: 502, error: reason });
      this.pendingDeliveries.delete(deliveryId);
    }
  }

  private clearSession(): void {
    if (this.session?.livenessTimer) clearInterval(this.session.livenessTimer);
    // A stream never outlives its tunnel: kill every open stream's socket.
    for (const stream of this.session?.streams.values() ?? []) {
      stream.destroy("the tunnel closed");
    }
    this.session = null;
  }

  private send(session: Session, frame: Frame): void {
    try {
      session.socket.send(encodeFrame(frame));
    // The send failure is logged; the stream's own timeout bounds the wait, and a dead
    // socket surfaces through the close handler below.
    // eslint-disable-next-line local/no-silent-catch
    } catch (error) {
      this.options.log(`[connector] failed to send a ${frame.type} frame: ${errorMessage(error)}`);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => {
      this.sleepResolve = () => {
        this.sleepResolve = null;
        resolve();
      };
      this.sleepTimer = setTimeout(() => this.sleepResolve?.(), ms);
      this.sleepTimer.unref();
    });
  }
}
