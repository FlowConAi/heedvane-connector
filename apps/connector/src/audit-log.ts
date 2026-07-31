// The connector's audit log: one JSON line per decision, metadata only. The connector
// is a pipe (docs/engineering/plans/code-host-connector-design-2026-07-24.md), so no
// entry ever carries a request or response body, a header value, or a credential; the
// customer's security team reads this log to see exactly what the hub asked for.

import type { WebhookVerificationScheme } from "@heedvane/connector-protocol";

export const AUDIT_DECISION = {
  allowed: "allowed",
  refused: "refused",
  accepted: "accepted",
} as const;
export type AuditDecision = (typeof AUDIT_DECISION)[keyof typeof AUDIT_DECISION];

export interface AuditLine {
  readonly at: string;
  readonly kind: "request" | "webhook" | "stream";
  readonly decision: AuditDecision;
  readonly reason: string;
  readonly requestId?: string;
  readonly method?: string;
  readonly path?: string;
  readonly queryParamNames?: readonly string[];
  readonly upstreamStatus?: number;
  readonly durationMs?: number;
  readonly deliveryId?: string;
  readonly event?: string;
  readonly verificationScheme?: WebhookVerificationScheme;
  readonly streamId?: string;
  readonly target?: string;
  readonly bytesIn?: number;
  readonly bytesOut?: number;
}

export interface RequestAuditInput {
  readonly requestId: string;
  readonly method: string;
  readonly path: string;
  readonly queryParamNames: readonly string[];
  readonly decision: AuditDecision;
  readonly reason: string;
  readonly upstreamStatus?: number;
  readonly durationMs?: number;
}

export interface WebhookAuditInput {
  readonly deliveryId: string;
  readonly event: string;
  readonly verificationScheme: WebhookVerificationScheme;
  readonly decision: AuditDecision;
  readonly reason: string;
}

export interface StreamAuditInput {
  readonly streamId: string;
  readonly target: string;
  readonly decision: AuditDecision;
  readonly reason: string;
  readonly bytesIn?: number;
  readonly bytesOut?: number;
}

export class AuditLog {
  constructor(
    private readonly sink: (line: AuditLine) => void = (line) => console.log(`[connector-audit] ${JSON.stringify(line)}`),
  ) {}

  public recordRequest(input: RequestAuditInput): void {
    this.sink({
      at: new Date().toISOString(),
      kind: "request",
      requestId: input.requestId,
      method: input.method,
      path: input.path,
      queryParamNames: input.queryParamNames,
      decision: input.decision,
      reason: input.reason,
      ...(input.upstreamStatus !== undefined ? { upstreamStatus: input.upstreamStatus } : {}),
      ...(input.durationMs !== undefined ? { durationMs: input.durationMs } : {}),
    });
  }

  public recordWebhook(input: WebhookAuditInput): void {
    this.sink({
      at: new Date().toISOString(),
      kind: "webhook",
      deliveryId: input.deliveryId,
      event: input.event,
      verificationScheme: input.verificationScheme,
      decision: input.decision,
      reason: input.reason,
    });
  }

  public recordStream(input: StreamAuditInput): void {
    this.sink({
      at: new Date().toISOString(),
      kind: "stream",
      streamId: input.streamId,
      target: input.target,
      decision: input.decision,
      reason: input.reason,
      ...(input.bytesIn !== undefined ? { bytesIn: input.bytesIn } : {}),
      ...(input.bytesOut !== undefined ? { bytesOut: input.bytesOut } : {}),
    });
  }
}
