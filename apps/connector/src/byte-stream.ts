// One raw bidirectional byte stream (protocol 2): the gateway opens it with a target,
// the connector dials that target inside the customer network, and bytes flow both
// ways as stream-data chunks under receiver-advertised flow control. The connector is
// a pipe on this path: the stream usually carries TLS end-to-end between the hub's
// client and the GitLab, so the bytes are opaque and GITLAB_CA_FILE is not involved
// here (it governs the request/response path in gitlab-forwarder.ts).
//
// Load-bearing rules:
// - Accepted targets are the configured GitLab's authority (GITLAB_BASE_URL, the
//   connector's ROUTE) and the instance's registered identity (instanceBaseUrl from
//   the server-hello, the clone URL's authority). The spec separates identity from
//   route deliberately; anything matching neither is target-refused, named, and
//   audit-logged. The dial ALWAYS goes to the route, never to the identity address.
// - Flow control is honored in both directions: never send past the peer's credit, and
//   a peer that runs past ours is flow-control-violated and closed.
// - A stream never outlives its tunnel: destroy() is called on tunnel death.

import { connect as netConnect, type Socket } from "node:net";

import {
  DEFAULT_STREAM_WINDOW_BYTES,
  MAX_STREAM_DATA_CHUNK_BYTES,
  type CapabilityProfile,
  type Frame,
  type StreamCloseFrame,
  type StreamDataFrame,
  type StreamErrorCode,
  type StreamTarget,
  type StreamWindowFrame,
} from "@heedvane/connector-protocol";

import { AUDIT_DECISION, type AuditDecision, type AuditLog } from "./audit-log.js";

export interface GitLabAuthority {
  readonly host: string;
  readonly port: number;
}

/** The one dialable authority for byte streams: host and port of GITLAB_BASE_URL. */
export function gitLabAuthorityFor(baseUrl: string): GitLabAuthority {
  const url = new URL(baseUrl);
  return {
    host: url.hostname.toLowerCase(),
    port: Number(url.port) || (url.protocol === "https:" ? 443 : 80),
  };
}

/** Clone is a read: profilePermits already lets the read-only profile serve
 *  git-upload-pack, and a byte stream is the same fetch one layer down, so BOTH
 *  capability profiles permit a stream. What a profile refuses (writes) is enforced
 *  above this pipe by the signed allowlist, never by the pipe. Kept as a named check so
 *  a future third profile trips here deliberately rather than silently. */
export function profilePermitsStream(_profile: CapabilityProfile): boolean {
  return true;
}

const DEFAULT_CONNECT_TIMEOUT_MS = 15_000;

export interface ByteStreamOptions {
  readonly streamId: string;
  readonly target: StreamTarget;
  /** The dial: GITLAB_BASE_URL's authority. This is the connector's ROUTE to the
   *  GitLab; it is always where the TCP connection goes. */
  readonly route: GitLabAuthority;
  /** The instance's registered IDENTITY (instanceBaseUrl from the server-hello), also
   *  an accepted stream target: the clone URL is identity, the tunnel is route, and
   *  the spec separates the two deliberately. Null when the gateway's hello did not
   *  carry one (older gateway), in which case only the route is accepted. */
  readonly identity: GitLabAuthority | null;
  readonly profile: CapabilityProfile;
  readonly send: (frame: Frame) => void;
  readonly auditLog: AuditLog;
  readonly log: (message: string) => void;
  readonly onFinalized: (streamId: string) => void;
  readonly connectTimeoutMs?: number;
  /** Test seam for the connect-timeout path; production dials with net.connect. */
  readonly dialImpl?: typeof netConnect;
}

export class GitLabByteStream {
  private socket: Socket | null = null;
  private connected = false;
  private peerInFlight = 0;
  private sendCredit = DEFAULT_STREAM_WINDOW_BYTES;
  private readonly outboundBuffer: Buffer[] = [];
  private readonly inboundQueue: Buffer[] = [];
  private inboundWriting = false;
  private remoteEnded = false;
  private gatewayClosed = false;
  private selfClosed = false;
  private finalized = false;
  private bytesIn = 0;
  private bytesOut = 0;
  private readonly connectTimeoutMs: number;

  constructor(private readonly options: ByteStreamOptions) {
    this.connectTimeoutMs = options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS;
  }

  public async open(): Promise<void> {
    if (!this.targetPermitted() || !profilePermitsStream(this.options.profile)) {
      const requested = `${this.options.target.host}:${this.options.target.port}`;
      this.emit({
        type: "stream-open-ack",
        streamId: this.options.streamId,
        ok: false,
        code: "target-refused",
        message: `stream target ${requested} ${this.refusalReason()}`,
      });
      this.finish("target-refused", AUDIT_DECISION.refused);
      return;
    }
    this.dial();
  }

  public onData(frame: StreamDataFrame): void {
    if (this.finalized) return;
    const chunk = Buffer.from(frame.dataBase64, "base64");
    this.peerInFlight += chunk.length;
    if (this.peerInFlight > DEFAULT_STREAM_WINDOW_BYTES) {
      this.failWith(
        "flow-control-violated",
        `the gateway exceeded the advertised stream window: ${this.peerInFlight} bytes in flight against the `
          + `${DEFAULT_STREAM_WINDOW_BYTES} byte initial window`,
      );
      return;
    }
    this.bytesIn += chunk.length;
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
    this.maybeFinalize();
  }

  /** Tunnel death: kill the socket and finalize locally without emitting frames. */
  public destroy(reason: string): void {
    if (this.finalized) return;
    this.finalized = true;
    this.socket?.destroy();
    this.auditClose(reason, AUDIT_DECISION.allowed);
    this.options.onFinalized(this.options.streamId);
  }

  private targetPermitted(): boolean {
    if (this.matchesAuthority(this.options.route)) return true;
    return this.options.identity !== null && this.matchesAuthority(this.options.identity);
  }

  private matchesAuthority(authority: GitLabAuthority): boolean {
    return (
      this.options.target.host.toLowerCase() === authority.host
      && this.options.target.port === authority.port
    );
  }

  private routeText(): string {
    return `${this.options.route.host}:${this.options.route.port}`;
  }

  private refusalReason(): string {
    const route = this.routeText();
    if (this.options.identity === null) {
      return `is not the configured GitLab ${route}; the connector dials its code host and nothing else`;
    }
    const identity = `${this.options.identity.host}:${this.options.identity.port}`;
    return `matches neither the GitLab route ${route} nor the instance identity ${identity}; `
      + "the connector dials its code host and nothing else";
  }

  private dial(): void {
    const dial = this.options.dialImpl ?? netConnect;
    // The dial ALWAYS goes to the route, never to the (identity-shaped) target: the
    // identity is who the clone is for, the route is how this connector reaches it.
    const socket = dial({ host: this.options.route.host, port: this.options.route.port });
    this.socket = socket;
    const timer = setTimeout(() => this.onConnectTimeout(socket), this.connectTimeoutMs);
    timer.unref();
    socket.once("connect", () => {
      clearTimeout(timer);
      this.onConnected(socket);
    });
    socket.once("error", (error: Error) => {
      clearTimeout(timer);
      this.onSocketError(error);
    });
  }

  private onConnectTimeout(socket: Socket): void {
    if (this.finalized || this.connected) return;
    socket.destroy();
    this.emit({
      type: "stream-open-ack",
      streamId: this.options.streamId,
      ok: false,
      code: "connect-timeout",
      message: `connecting to the GitLab at ${this.routeText()} timed out after ${this.connectTimeoutMs}ms`,
    });
    this.finish("connect-timeout", AUDIT_DECISION.refused);
  }

  private onConnected(socket: Socket): void {
    if (this.finalized) return;
    this.connected = true;
    this.emit({ type: "stream-open-ack", streamId: this.options.streamId, ok: true });
    this.options.auditLog.recordStream({
      streamId: this.options.streamId,
      target: `${this.options.target.host}:${this.options.target.port}`,
      decision: AUDIT_DECISION.allowed,
      reason: "stream opened to the configured GitLab",
    });
    socket.on("data", (chunk: Buffer) => this.onSocketData(chunk));
    socket.on("end", () => this.onSocketEnd());
    socket.on("close", (hadError: boolean) => this.onSocketClose(hadError));
    this.drainInbound();
  }

  private onSocketError(error: Error): void {
    if (this.finalized) return;
    if (!this.connected) {
      this.emit({
        type: "stream-open-ack",
        streamId: this.options.streamId,
        ok: false,
        code: "connect-refused",
        message: `the GitLab at ${this.routeText()} could not be reached: ${error.message}`,
      });
      this.finish("connect-refused", AUDIT_DECISION.refused);
      return;
    }
    this.failWith("upstream-reset", `the GitLab socket failed mid-stream: ${error.message}`);
  }

  private drainInbound(): void {
    const socket = this.socket;
    if (socket === null || this.inboundWriting || this.finalized) return;
    const chunk = this.inboundQueue.shift();
    if (chunk === undefined) {
      if (this.gatewayClosed && !socket.destroyed) socket.end();
      return;
    }
    this.inboundWriting = true;
    socket.write(chunk, () => {
      this.inboundWriting = false;
      this.topUp(chunk.length);
      this.drainInbound();
    });
  }

  /** Consumed inbound bytes become fresh credit for the peer. */
  private topUp(bytes: number): void {
    if (this.finalized) return;
    this.peerInFlight -= bytes;
    this.emit({ type: "stream-window", streamId: this.options.streamId, bytes });
  }

  private onSocketData(chunk: Buffer): void {
    if (this.finalized) return;
    this.bytesOut += chunk.length;
    for (let offset = 0; offset < chunk.length; offset += MAX_STREAM_DATA_CHUNK_BYTES) {
      this.outboundBuffer.push(chunk.subarray(offset, offset + MAX_STREAM_DATA_CHUNK_BYTES));
    }
    this.pumpOutbound();
  }

  /** Send while credit allows, splitting the head chunk when only part of it fits:
   *  remaining credit is always usable, so a peer window is never stranded by chunk
   *  alignment (TCP segmentation differs by platform). The socket is paused whenever
   *  the buffer cannot drain, so a slow gateway never grows the buffer unboundedly. */
  private pumpOutbound(): void {
    while (this.outboundBuffer.length > 0 && this.sendCredit > 0) {
      const head = this.outboundBuffer[0];
      if (head === undefined) break;
      const slice = head.length <= this.sendCredit ? head : head.subarray(0, this.sendCredit);
      this.sendCredit -= slice.length;
      if (slice.length === head.length) {
        this.outboundBuffer.shift();
      } else {
        this.outboundBuffer[0] = head.subarray(slice.length);
      }
      this.emit({ type: "stream-data", streamId: this.options.streamId, dataBase64: slice.toString("base64") });
    }
    if (this.outboundBuffer.length > 0) {
      this.socket?.pause();
      return;
    }
    // The buffer drained, so the socket may flow again; resume is a no-op when unpaused.
    this.socket?.resume();
    if (this.remoteEnded) this.closeSelf();
  }

  private onSocketEnd(): void {
    this.remoteEnded = true;
    this.pumpOutbound();
  }

  private onSocketClose(hadError: boolean): void {
    if (this.finalized) return;
    if (!hadError && !this.selfClosed) this.closeSelf();
    this.finish(hadError ? "socket closed after an error" : "socket closed", AUDIT_DECISION.allowed);
  }

  private closeSelf(): void {
    if (this.selfClosed) return;
    this.selfClosed = true;
    this.emit({ type: "stream-close", streamId: this.options.streamId, reason: "done" });
    this.maybeFinalize();
  }

  private maybeFinalize(): void {
    if (this.gatewayClosed && this.selfClosed) this.finish("done", AUDIT_DECISION.allowed);
  }

  private failWith(code: StreamErrorCode, message: string): void {
    this.emit({ type: "stream-error", streamId: this.options.streamId, code, message });
    this.socket?.destroy();
    this.finish(code, AUDIT_DECISION.allowed);
  }

  private emit(frame: Frame): void {
    if (this.finalized) return;
    this.options.send(frame);
  }

  private finish(reason: string, decision: AuditDecision): void {
    if (this.finalized) return;
    this.finalized = true;
    this.socket?.destroy();
    this.auditClose(reason, decision);
    this.options.onFinalized(this.options.streamId);
  }

  private auditClose(reason: string, decision: AuditDecision): void {
    this.options.auditLog.recordStream({
      streamId: this.options.streamId,
      target: `${this.options.target.host}:${this.options.target.port}`,
      decision,
      reason: `stream closed: ${reason}`,
      bytesIn: this.bytesIn,
      bytesOut: this.bytesOut,
    });
  }
}
