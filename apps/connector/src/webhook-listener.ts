// The local webhook intake: the customer GitLab POSTs deliveries here, inside the
// customer network. Verification happens locally before anything crosses the tunnel
// with GitLab 19's Standard Webhooks HMAC, and the local 200 is
// sent only after the gateway ack, so GitLab's retry semantics still reflect whether
// the hub actually queued the delivery. Bodies are never logged or persisted; the
// audit record carries delivery metadata only (the connector is a pipe).

import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo, Socket } from "node:net";

import type { WebhookFrame, WebhookVerificationScheme } from "@heedvane/connector-protocol";

import { AUDIT_DECISION, type AuditLog } from "./audit-log.js";

export interface WebhookAck {
  readonly ok: boolean;
  readonly status: number;
  readonly deliveryId?: string;
  readonly error?: string;
}

export interface WebhookListenerOptions {
  readonly host: string;
  readonly port: number;
  readonly secret: string | null;
  readonly ackTimeoutMs: number;
  readonly maxBodyBytes: number;
  readonly deliver: (frame: WebhookFrame) => Promise<WebhookAck>;
  readonly auditLog: AuditLog;
  readonly log?: (message: string) => void;
}

const WEBHOOK_PATH = "/webhooks/gitlab";
const SIGNING_SECRET_PREFIX = "whsec_";
const SIGNATURE_TIMESTAMP_TOLERANCE_SECONDS = 300;

const HEADER = {
  event: "x-gitlab-event",
  eventUuid: "x-gitlab-event-uuid",
  webhookId: "webhook-id",
  webhookTimestamp: "webhook-timestamp",
  webhookSignature: "webhook-signature",
} as const;

const SIGNING_SCHEME = "signing-token" satisfies WebhookVerificationScheme;

type Verification =
  | { readonly ok: true; readonly scheme: WebhookVerificationScheme }
  | { readonly ok: false; readonly status: number; readonly reason: string };

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function headerText(message: IncomingMessage, name: string): string | null {
  const value = message.headers[name];
  if (typeof value === "string" && value.length > 0) return value;
  if (Array.isArray(value) && typeof value[0] === "string" && value[0].length > 0) return value[0];
  return null;
}

function signatureMatches(candidate: string, expected: Buffer): boolean {
  const VERSION_PREFIX = "v1,";
  if (!candidate.startsWith(VERSION_PREFIX)) return false;
  const presented = Buffer.from(candidate.slice(VERSION_PREFIX.length), "base64");
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(presented, expected);
}

/** GitLab 19 signs with the Standard Webhooks scheme: HMAC-SHA256 over
 *  "webhook-id.webhook-timestamp.body" keyed by the base64 part of a whsec_ secret,
 *  with a timestamp tolerance against replay. */
function verifyStandardWebhook(input: {
  secret: string;
  message: IncomingMessage;
  body: Buffer;
}): Verification {
  const id = headerText(input.message, HEADER.webhookId);
  const timestamp = headerText(input.message, HEADER.webhookTimestamp);
  const signatureHeader = headerText(input.message, HEADER.webhookSignature);
  if (id === null || timestamp === null || signatureHeader === null) {
    return { ok: false, status: 401, reason: "the signing headers are incomplete" };
  }
  const ageSeconds = Math.abs(Math.floor(Date.now() / 1_000) - Number(timestamp));
  if (!Number.isFinite(ageSeconds) || ageSeconds > SIGNATURE_TIMESTAMP_TOLERANCE_SECONDS) {
    return { ok: false, status: 401, reason: "the webhook timestamp is outside the tolerance window" };
  }
  const key = Buffer.from(input.secret.slice(SIGNING_SECRET_PREFIX.length), "base64");
  const expected = createHmac("sha256", key).update(`${id}.${timestamp}.${input.body.toString("utf8")}`).digest();
  const candidates = signatureHeader.split(/\s+/);
  if (candidates.some((candidate) => signatureMatches(candidate, expected))) {
    return { ok: true, scheme: SIGNING_SCHEME };
  }
  return { ok: false, status: 401, reason: "the webhook signature does not match" };
}

function verifyDelivery(message: IncomingMessage, body: Buffer, secret: string | null): Verification {
  if (secret === null) {
    return { ok: false, status: 503, reason: "WEBHOOK_SECRET is not configured on the connector" };
  }
  if (!secret.startsWith(SIGNING_SECRET_PREFIX)) {
    return {
      ok: false,
      status: 503,
      reason: "WEBHOOK_SECRET must be the whsec_ signing token returned by GitLab 19 or newer",
    };
  }
  return verifyStandardWebhook({ secret, message, body });
}

function readBody(message: IncomingMessage, maxBodyBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;
    message.on("data", (chunk: Buffer) => {
      received += chunk.length;
      if (received > maxBodyBytes) {
        // Keep draining into the void so the client finishes its upload and can read
        // our 413; the socket is closed after the response flushes.
        message.removeAllListeners("data");
        message.resume();
        reject(new BodyTooLargeError(`the delivery body exceeds the ${maxBodyBytes} byte limit`));
        return;
      }
      chunks.push(chunk);
    });
    message.on("end", () => resolve(Buffer.concat(chunks)));
    message.on("error", reject);
  });
}

class BodyTooLargeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BodyTooLargeError";
  }
}

function headerRecord(message: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(message.headers)) {
    if (value === undefined) continue;
    headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

function respond(response: ServerResponse, status: number, text: string): void {
  response.writeHead(status, { "content-type": "text/plain; charset=utf-8" });
  response.end(text);
}

interface DeliveryContext {
  readonly request: IncomingMessage;
  readonly response: ServerResponse;
  readonly event: string;
  readonly scheme: WebhookVerificationScheme;
  readonly body: Buffer;
}

/** Ack statuses are produced by the hub (mirrored through the gateway) or by the
 *  tunnel itself (502 not connected, 504 ack timeout); all are honest to return. */
function ackHttpStatus(ack: WebhookAck): number {
  if (ack.status >= 400 && ack.status <= 599) return ack.status;
  return 502;
}

export class WebhookListener {
  private server: Server | null = null;
  private readonly sockets = new Set<Socket>();
  private actualPort = 0;

  constructor(private readonly options: WebhookListenerOptions) {}

  public async start(): Promise<void> {
    this.server = createServer((request, response) => {
      void this.onRequest(request, response);
    });
    this.server.on("connection", (socket: Socket) => {
      this.sockets.add(socket);
      socket.on("close", () => this.sockets.delete(socket));
    });
    await new Promise<void>((resolve, reject) => {
      this.server?.listen(this.options.port, this.options.host, () => resolve());
      this.server?.once("error", reject);
    });
    this.actualPort = (this.server.address() as AddressInfo).port;
  }

  public port(): number {
    return this.actualPort;
  }

  public async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
    this.server = null;
  }

  private async onRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
    if (request.method !== "POST" || request.url !== WEBHOOK_PATH) {
      respond(response, 404, "not found");
      return;
    }
    let body: Buffer;
    try {
      body = await readBody(request, this.options.maxBodyBytes);
    } catch (error) {
      const status = error instanceof BodyTooLargeError ? 413 : 400;
      response.writeHead(status, { "content-type": "text/plain; charset=utf-8", connection: "close" });
      response.end(errorMessage(error), () => request.socket.destroy());
      return;
    }
    const event = headerText(request, HEADER.event);
    if (event === null) {
      respond(response, 400, `missing ${HEADER.event} header`);
      return;
    }
    const verification = verifyDelivery(request, body, this.options.secret);
    if (!verification.ok) {
      this.options.auditLog.recordWebhook({
        deliveryId: headerText(request, HEADER.eventUuid) ?? "unknown",
        event,
        verificationScheme: SIGNING_SCHEME,
        decision: AUDIT_DECISION.refused,
        reason: verification.reason,
      });
      respond(response, verification.status, verification.reason);
      return;
    }
    await this.deliverAndRespond({ request, response, event, scheme: verification.scheme, body });
  }

  private async deliverAndRespond(context: DeliveryContext): Promise<void> {
    const { request, response, event, scheme } = context;
    const ack = await this.forwardWithTimeout(context);
    if (ack.ok) {
      this.options.auditLog.recordWebhook({
        deliveryId: ack.deliveryId ?? "unknown",
        event,
        verificationScheme: scheme,
        decision: AUDIT_DECISION.accepted,
        reason: `queued by the hub as ${ack.deliveryId ?? "unknown"}`,
      });
      respond(response, 200, "delivered");
      return;
    }
    this.options.auditLog.recordWebhook({
      deliveryId: headerText(request, HEADER.eventUuid) ?? "unknown",
      event,
      verificationScheme: scheme,
      decision: AUDIT_DECISION.refused,
      reason: ack.error ?? `the hub answered HTTP ${ack.status}`,
    });
    respond(response, ackHttpStatus(ack), ack.error ?? "the delivery was not accepted");
  }

  private async forwardWithTimeout(context: DeliveryContext): Promise<WebhookAck> {
    const { request, event, scheme, body } = context;
    const frame: WebhookFrame = {
      type: "webhook",
      streamId: randomUUID(),
      deliveryId: headerText(request, HEADER.webhookId) ?? headerText(request, HEADER.eventUuid) ?? randomUUID(),
      event,
      headers: headerRecord(request),
      bodyBase64: body.toString("base64"),
      verificationScheme: scheme,
    };
    let timer: NodeJS.Timeout | null = null;
    const timeout = new Promise<WebhookAck>((resolve) => {
      timer = setTimeout(() => {
        resolve({
          ok: false,
          status: 504,
          error: `the gateway did not acknowledge delivery ${frame.deliveryId} within ${this.options.ackTimeoutMs}ms`,
        });
      }, this.options.ackTimeoutMs);
      timer.unref?.();
    });
    try {
      const ack = await Promise.race([this.options.deliver(frame), timeout]);
      return ack;
    } catch (error) {
      this.options.log?.(`[connector] webhook delivery ${frame.deliveryId} failed in the tunnel: ${errorMessage(error)}`);
      return { ok: false, status: 502, error: `the tunnel failed to deliver: ${errorMessage(error)}` };
    } finally {
      if (timer) clearTimeout(timer);
    }
  }
}
