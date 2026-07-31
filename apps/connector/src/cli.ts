#!/usr/bin/env node
// heedvane-connector: the customer-run half of the code-host connector. Boot order:
// parse config (fail fast with the variable named), load the two trust stores, resolve
// the hub allowlist public key (the configured file, or a fetch from the hub derived
// from the gateway URL), start the local webhook listener, then run the tunnel until
// SIGINT/SIGTERM or a terminal refusal. Exit codes: 0 clean stop, 1 config error or
// terminal gateway refusal.

import { createPublicKey, type KeyObject } from "node:crypto";
import { readFileSync } from "node:fs";
import { hostname } from "node:os";

import { allowlistKeyUrl, AllowlistKeyError, fetchAllowlistPublicKey } from "./allowlist-key.js";
import { AuditLog } from "./audit-log.js";
import { ConfigError, loadConfig, type ConnectorConfig } from "./config.js";
import { persistCredentialFile } from "./credential-file.js";
import { ConnectorTunnel } from "./tunnel.js";
import { CONNECTOR_VERSION } from "./version.js";
import { WebhookListener } from "./webhook-listener.js";

function log(message: string): void {
  console.log(message);
}

function readOptionalFile(path: string | null, variable: string): Buffer | undefined {
  if (path === null) return undefined;
  try {
    return readFileSync(path);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`${variable} points at ${path}, which could not be read: ${reason}`);
  }
}

function readAllowlistPublicKey(path: string): KeyObject {
  let pem: string;
  try {
    pem = readFileSync(path, "utf8");
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(
      `HUB_ALLOWLIST_PUBLIC_KEY_FILE points at ${path}, which could not be read: ${reason}. `
        + "Ask the Heedvane operator for the allowlist public key matching the gateway's signing key.",
    );
  }
  try {
    return createPublicKey(pem);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`HUB_ALLOWLIST_PUBLIC_KEY_FILE at ${path} is not a usable public key: ${reason}`);
  }
}

/** The verification key is mandatory but the FILE is not: without one, the key comes
 *  from the hub over the same egress path as the tunnel. A fetch failure is a boot
 *  error naming the URL, never a skip of allowlist verification. */
async function resolveAllowlistPublicKey(config: ConnectorConfig, gatewayCa: Buffer | undefined): Promise<KeyObject> {
  if (config.hubAllowlistPublicKeyFile !== null) {
    return readAllowlistPublicKey(config.hubAllowlistPublicKeyFile);
  }
  const keyUrl = allowlistKeyUrl(config.gatewayUrl);
  log(`[connector] HUB_ALLOWLIST_PUBLIC_KEY_FILE is not set; fetching the hub allowlist public key from ${keyUrl}`);
  try {
    return await fetchAllowlistPublicKey({
      keyUrl,
      proxyUrl: config.proxyUrl,
      ...(gatewayCa !== undefined ? { ca: gatewayCa } : {}),
    });
  } catch (error) {
    if (error instanceof AllowlistKeyError) throw new ConfigError(error.message);
    throw error;
  }
}

function webhookBaseUrl(config: ConnectorConfig): string {
  const host = config.advertiseHost ?? hostname();
  return `http://${host}:${config.webhookListenPort}/webhooks/gitlab`;
}

function persistCredential(config: ConnectorConfig): (credential: string) => void {
  return (credential) => {
    if (config.credentialFile !== null) {
      persistCredentialFile(config.credentialFile, credential);
      log(`[connector] enrollment complete; the long-lived credential is persisted to ${config.credentialFile}`);
      return;
    }
    log(
      "[connector] enrollment complete. HEEDVANE_CREDENTIAL_FILE is not set, so the credential lives only in "
        + "this process's memory; a restart needs it in HEEDVANE_CONNECTOR_CREDENTIAL or a mounted credential file.",
    );
  };
}

async function main(): Promise<number> {
  const config = loadConfig({ env: process.env });
  const gatewayCa = readOptionalFile(config.gatewayCaFile, "HEEDVANE_GATEWAY_CA_FILE");
  const gitlabCa = readOptionalFile(config.gitlabCaFile, "GITLAB_CA_FILE");
  const allowlistPublicKey = await resolveAllowlistPublicKey(config, gatewayCa);
  const auditLog = new AuditLog();
  const tunnel = new ConnectorTunnel({
    config,
    allowlistPublicKey,
    auditLog,
    log,
    onCredentialIssued: persistCredential(config),
    webhookBaseUrl: webhookBaseUrl(config),
    ...(gatewayCa !== undefined ? { gatewayCa } : {}),
    ...(gitlabCa !== undefined ? { gitlabCa } : {}),
  });
  const listener = new WebhookListener({
    host: config.webhookListenHost,
    port: config.webhookListenPort,
    secret: config.webhookSecret,
    ackTimeoutMs: 15_000,
    maxBodyBytes: 10 * 1024 * 1024,
    deliver: (frame) => tunnel.deliverWebhook(frame),
    auditLog,
    log,
  });
  await listener.start();
  log(
    `[connector] heedvane-connector ${CONNECTOR_VERSION}: webhook listener on `
      + `${config.webhookListenHost}:${listener.port()} advertising ${webhookBaseUrl(config)}, `
      + `serving ${config.gitlabBaseUrl} with the "${config.capabilityProfile}" capability profile`,
  );
  const shutdown = (signal: string): void => {
    log(`[connector] ${signal} received; shutting down`);
    tunnel.stop();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  const exitCode = await tunnel.run();
  await listener.close();
  return exitCode;
}

try {
  const exitCode = await main();
  process.exitCode = exitCode;
} catch (error) {
  if (error instanceof ConfigError) {
    console.error(`[connector] configuration error: ${error.message}`);
  } else {
    console.error(`[connector] fatal error: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}`);
  }
  process.exitCode = 1;
}
