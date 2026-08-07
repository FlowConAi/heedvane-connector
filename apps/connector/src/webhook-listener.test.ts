import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";

import type { WebhookFrame } from "@heedvane/connector-protocol";

import { AuditLog, type AuditLine } from "./audit-log.js";
import { WebhookListener, type WebhookAck } from "./webhook-listener.js";

const SIGNING_KEY = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
const SECRET = `whsec_${SIGNING_KEY.toString("base64")}`;

interface Harness {
  listener: WebhookListener;
  baseUrl: string;
  deliveries: WebhookFrame[];
  auditLines: AuditLine[];
  ackWith: (ack: WebhookAck) => void;
  holdAck: () => void;
  close: () => Promise<void>;
}

async function startListener(overrides: Partial<Parameters<typeof buildOptions>[0]> = {}): Promise<Harness> {
  const options = buildOptions(overrides);
  const deliveries: WebhookFrame[] = [];
  const auditLines: AuditLine[] = [];
  let pending: { resolve: (ack: WebhookAck) => void; mode: "auto" | "held" } | null = null;
  const listener = new WebhookListener({
    ...options,
    auditLog: new AuditLog((line) => auditLines.push(line)),
    deliver: (frame) => {
      deliveries.push(frame);
      if (pending?.mode === "held") {
        return new Promise<WebhookAck>((resolve) => {
          pending = { resolve, mode: "held" };
        });
      }
      return Promise.resolve({ ok: true, status: 200, deliveryId: "delivery-queue-1" });
    },
  });
  await listener.start();
  return {
    listener,
    baseUrl: `http://127.0.0.1:${listener.port()}`,
    deliveries,
    auditLines,
    ackWith: (ack) => pending?.resolve(ack),
    holdAck: () => {
      pending = { resolve: () => undefined, mode: "held" };
    },
    close: () => listener.close(),
  };
}

function buildOptions(overrides: Partial<{
  secret: string | null;
  ackTimeoutMs: number;
  maxBodyBytes: number;
}>): { host: string; port: number; secret: string | null; ackTimeoutMs: number; maxBodyBytes: number } {
  return {
    host: "127.0.0.1",
    port: 0,
    secret: overrides.secret === undefined ? SECRET : overrides.secret,
    ackTimeoutMs: overrides.ackTimeoutMs ?? 5_000,
    maxBodyBytes: overrides.maxBodyBytes ?? 1_048_576,
  };
}

function hookHeaders(body = "{}", overrides: Record<string, string> = {}): Record<string, string> {
  const timestamp = String(Math.floor(Date.now() / 1000));
  return {
    "content-type": "application/json",
    "x-gitlab-event": "Push Hook",
    "x-gitlab-event-uuid": "uuid-1234",
    "webhook-id": "uuid-1234",
    "webhook-timestamp": timestamp,
    "webhook-signature": standardWebhookSignature({ id: "uuid-1234", timestamp, body, key: SIGNING_KEY }),
    ...overrides,
  };
}

test("a verified GitLab 19 signing token is forwarded as a signing-token webhook frame", async () => {
  const harness = await startListener();
  try {
    const body = JSON.stringify({ object_kind: "push" });
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(body),
      body,
    });
    assert.equal(response.status, 200);
    assert.equal(harness.deliveries.length, 1);
    const frame = harness.deliveries[0];
    assert.equal(frame?.verificationScheme, "signing-token");
    assert.equal(frame?.event, "Push Hook");
    assert.equal(frame?.deliveryId, "uuid-1234");
    assert.equal(frame?.headers["webhook-id"], "uuid-1234");
    assert.equal(Buffer.from(frame?.bodyBase64 ?? "", "base64").toString("utf8"), '{"object_kind":"push"}');
    assert.equal(harness.auditLines.at(-1)?.decision, "accepted");
  } finally {
    await harness.close();
  }
});

test("the local GitLab gets its 200 only after the gateway ack arrives", async () => {
  const harness = await startListener();
  try {
    harness.holdAck();
    let settled = false;
    const responsePromise = fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    }).then((response) => {
      settled = true;
      return response;
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    assert.equal(settled, false, "the HTTP response completed before the gateway ack");
    assert.equal(harness.deliveries.length, 1, "the frame was not forwarded while the ack was held");
    harness.ackWith({ ok: true, status: 200, deliveryId: "delivery-queue-9" });
    const response = await responsePromise;
    assert.equal(response.status, 200);
  } finally {
    await harness.close();
  }
});

test("a GitLab 18 X-Gitlab-Token delivery is refused and never forwarded", async () => {
  const harness = await startListener();
  try {
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-gitlab-event": "Push Hook",
        "x-gitlab-token": "classic-secret",
      },
      body: "{}",
    });
    assert.equal(response.status, 401);
    assert.equal(harness.deliveries.length, 0);
    assert.equal(harness.auditLines.at(-1)?.decision, "refused");
  } finally {
    await harness.close();
  }
});

test("an unconfigured WEBHOOK_SECRET refuses truthfully instead of accepting everything", async () => {
  const harness = await startListener({ secret: null });
  try {
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    });
    assert.equal(response.status, 503);
    assert.equal(harness.deliveries.length, 0);
  } finally {
    await harness.close();
  }
});

test("a hub refusal ack is mirrored to the local GitLab with its real status", async () => {
  const harness = await startListener();
  try {
    harness.holdAck();
    const responsePromise = fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    harness.ackWith({ ok: false, status: 422, error: "no webhook subscription matches this connector" });
    const response = await responsePromise;
    assert.equal(response.status, 422);
  } finally {
    await harness.close();
  }
});

test("a missing ack inside the budget is a 504, not a hung connection", async () => {
  const harness = await startListener({ ackTimeoutMs: 150 });
  try {
    harness.holdAck();
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    });
    assert.equal(response.status, 504);
  } finally {
    await harness.close();
  }
});

function signingSecret(): { secret: string; key: Buffer } {
  return { secret: SECRET, key: SIGNING_KEY };
}

function standardWebhookSignature(input: { id: string; timestamp: string; body: string; key: Buffer }): string {
  const hmac = createHmac("sha256", input.key);
  hmac.update(`${input.id}.${input.timestamp}.${input.body}`);
  return `v1,${hmac.digest("base64")}`;
}

test("GitLab 19 signing-token: a valid Standard Webhooks HMAC is accepted", async () => {
  const { secret, key } = signingSecret();
  const harness = await startListener({ secret });
  try {
    const body = JSON.stringify({ object_kind: "merge_request" });
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = standardWebhookSignature({ id: "msg-1", timestamp, body, key });
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(body, {
        "webhook-id": "msg-1",
        "webhook-timestamp": timestamp,
        "webhook-signature": signature,
      }),
      body,
    });
    assert.equal(response.status, 200);
    assert.equal(harness.deliveries[0]?.verificationScheme, "signing-token");
    assert.equal(harness.deliveries[0]?.deliveryId, "msg-1");
  } finally {
    await harness.close();
  }
});

test("GitLab 19 signing-token: a tampered body fails verification", async () => {
  const { secret, key } = signingSecret();
  const harness = await startListener({ secret });
  try {
    const timestamp = String(Math.floor(Date.now() / 1000));
    const signature = standardWebhookSignature({ id: "msg-1", timestamp, body: "original", key });
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders("tampered", {
        "webhook-id": "msg-1",
        "webhook-timestamp": timestamp,
        "webhook-signature": signature,
      }),
      body: "tampered",
    });
    assert.equal(response.status, 401);
    assert.equal(harness.deliveries.length, 0);
  } finally {
    await harness.close();
  }
});

test("a signing header with a non-whsec secret is refused", async () => {
  const harness = await startListener({ secret: "classic-secret" });
  try {
    const response = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    });
    assert.equal(response.status, 503);
    assert.equal(harness.deliveries.length, 0);
  } finally {
    await harness.close();
  }
});

test("other paths, missing event headers, and oversize bodies are refused", async () => {
  const harness = await startListener({ maxBodyBytes: 16 });
  try {
    const wrongPath = await fetch(`${harness.baseUrl}/webhooks/other`, {
      method: "POST",
      headers: hookHeaders(),
      body: "{}",
    });
    assert.equal(wrongPath.status, 404);
    const noEventHeaders = hookHeaders();
    delete noEventHeaders["x-gitlab-event"];
    const noEvent = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: noEventHeaders,
      body: "{}",
    });
    assert.equal(noEvent.status, 400);
    const oversize = await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(),
      body: "0123456789abcdef0123",
    });
    assert.equal(oversize.status, 413);
    assert.equal(harness.deliveries.length, 0);
  } finally {
    await harness.close();
  }
});

test("the webhook audit record never carries the delivery body", async () => {
  const harness = await startListener();
  try {
    const body = '{"secret_field":"DO NOT LOG"}';
    await fetch(`${harness.baseUrl}/webhooks/gitlab`, {
      method: "POST",
      headers: hookHeaders(body),
      body,
    });
    assert.ok(!JSON.stringify(harness.auditLines).includes("DO NOT LOG"), "audit log leaked a webhook body");
  } finally {
    await harness.close();
  }
});
