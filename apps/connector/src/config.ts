// Connector configuration from the environment. The primary variable names are the ones
// the hub's enrollment issuance writes into the docker run command
// (apps/web/src/lib/code-host/gitlab/connector-enrollment.ts); the short aliases keep
// hand-rolled deployments workable. Every parse failure names the variable and the
// expected shape, because the person reading the error is on the customer's side of the
// network and cannot inspect this process.

import { CAPABILITY_PROFILES, type CapabilityProfile } from "@heedvane/connector-protocol";

import { readCredentialFile } from "./credential-file.js";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export interface ConnectorConfig {
  readonly gatewayUrl: string;
  readonly enrollmentToken: string | null;
  readonly credential: string | null;
  readonly credentialFile: string | null;
  readonly gitlabBaseUrl: string;
  readonly gitlabToken: string | null;
  readonly connectorName: string | null;
  readonly capabilityProfile: CapabilityProfile;
  readonly proxyUrl: string | null;
  readonly gatewayCaFile: string | null;
  readonly gitlabCaFile: string | null;
  /** Null means boot fetches the key from the hub (see src/allowlist-key.ts). */
  readonly hubAllowlistPublicKeyFile: string | null;
  readonly webhookListenHost: string;
  readonly webhookListenPort: number;
  readonly webhookSecret: string | null;
  readonly advertiseHost: string | null;
  readonly requestTimeoutMs: number;
}

export interface LoadConfigInput {
  readonly env: Record<string, string | undefined>;
  readonly readCredentialFile?: (path: string) => string;
}

const DEFAULT_WEBHOOK_LISTEN_HOST = "0.0.0.0";
const DEFAULT_WEBHOOK_LISTEN_PORT = 8_080;
const DEFAULT_REQUEST_TIMEOUT_MS = 25_000;

function firstText(env: Record<string, string | undefined>, names: readonly string[]): string | null {
  for (const name of names) {
    const value = env[name]?.trim();
    if (value) return value;
  }
  return null;
}

function parseGatewayUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`HEEDVANE_GATEWAY_URL is not a valid URL: "${raw}". Expected ws(s)://host/connector-gateway.`);
  }
  if (url.protocol !== "ws:" && url.protocol !== "wss:") {
    throw new ConfigError(
      `HEEDVANE_GATEWAY_URL must use ws:// or wss://, got "${url.protocol}//". `
        + "Point it at the connector gateway, for example wss://api.heedvane.example/connector-gateway.",
    );
  }
  return raw.replace(/\/+$/, "");
}

function parseBaseUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`GITLAB_BASE_URL is not a valid URL: "${raw}". Expected an http(s) origin, for example https://gitlab.example.com.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new ConfigError(`GITLAB_BASE_URL must use http:// or https://, got "${url.protocol}//".`);
  }
  return raw.replace(/\/+$/, "");
}

function parseProfile(raw: string | null): CapabilityProfile {
  if (raw === null) return "read-only";
  if ((CAPABILITY_PROFILES as readonly string[]).includes(raw)) return raw as CapabilityProfile;
  throw new ConfigError(
    `HEEDVANE_CAPABILITY_PROFILE must be one of ${CAPABILITY_PROFILES.join(", ")}, got "${raw}".`,
  );
}

function parsePort(raw: string | null): number {
  if (raw === null) return DEFAULT_WEBHOOK_LISTEN_PORT;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new ConfigError(`WEBHOOK_LISTEN_PORT must be an integer between 1 and 65535, got "${raw}".`);
  }
  return port;
}

function parseTimeout(raw: string | null): number {
  if (raw === null) return DEFAULT_REQUEST_TIMEOUT_MS;
  const timeoutMs = Number(raw);
  if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
    throw new ConfigError(`GITLAB_REQUEST_TIMEOUT_MS must be a positive integer of milliseconds, got "${raw}".`);
  }
  return timeoutMs;
}

// Credential resolution order: an explicit env credential always wins; then a readable,
// non-empty credential FILE (a persisted credential proves enrollment already happened,
// so it wins over the still-configured but now-consumed enrollment token, which is the
// shape the systemd env file keeps after the first boot); then the enrollment token.
// A missing or empty file means first boot, not a crash. A file that exists but cannot
// be read falls through to the token when one is configured (enroll and overwrite),
// and is a named config error when nothing else can authenticate the connector.
function resolveCredential(input: LoadConfigInput, credentialFile: string | null): string | null {
  const fromEnv = firstText(input.env, ["HEEDVANE_CONNECTOR_CREDENTIAL"]);
  if (fromEnv !== null) return fromEnv;
  if (credentialFile === null) return null;
  return readCredentialIfPresent({
    reader: input.readCredentialFile ?? readCredentialFile,
    credentialFile,
    enrollmentToken: firstText(input.env, ["HEEDVANE_ENROLLMENT_TOKEN"]),
  });
}

interface CredentialFileRead {
  readonly reader: (path: string) => string;
  readonly credentialFile: string;
  readonly enrollmentToken: string | null;
}

function readCredentialIfPresent(read: CredentialFileRead): string | null {
  let raw: string;
  try {
    raw = read.reader(read.credentialFile);
  } catch (error) {
    return onCredentialReadFailure(read, error);
  }
  const trimmed = raw.trim();
  return trimmed === "" ? null : trimmed;
}

function onCredentialReadFailure(read: CredentialFileRead, error: unknown): string | null {
  if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
  if (read.enrollmentToken !== null) return null;
  const reason = error instanceof Error ? error.message : String(error);
  throw new ConfigError(
    `HEEDVANE_CREDENTIAL_FILE points at ${read.credentialFile}, which could not be read: ${reason}. `
      + "Fix the file, remove it, or set HEEDVANE_ENROLLMENT_TOKEN to enroll fresh.",
  );
}

export function loadConfig(input: LoadConfigInput): ConnectorConfig {
  const { env } = input;
  const gatewayUrlRaw = firstText(env, ["HEEDVANE_GATEWAY_URL", "HEEDVANE_CONNECTOR_GATEWAY_URL"]);
  if (gatewayUrlRaw === null) {
    throw new ConfigError("HEEDVANE_GATEWAY_URL is required: the ws(s) URL of the connector gateway.");
  }
  const gitlabBaseUrlRaw = firstText(env, ["GITLAB_BASE_URL"]);
  if (gitlabBaseUrlRaw === null) {
    throw new ConfigError("GITLAB_BASE_URL is required: the http(s) origin of the GitLab instance this connector serves.");
  }
  const credentialFile = firstText(env, ["HEEDVANE_CREDENTIAL_FILE"]);
  const enrollmentToken = firstText(env, ["HEEDVANE_ENROLLMENT_TOKEN"]);
  const credential = resolveCredential(input, credentialFile);
  if (enrollmentToken === null && credential === null) {
    throw new ConfigError(
      "Set HEEDVANE_ENROLLMENT_TOKEN for the first boot or HEEDVANE_CONNECTOR_CREDENTIAL "
        + "(or HEEDVANE_CREDENTIAL_FILE) for a restart; neither is configured.",
    );
  }
  const hubAllowlistPublicKeyFile = firstText(env, ["HUB_ALLOWLIST_PUBLIC_KEY_FILE"]);
  return {
    gatewayUrl: parseGatewayUrl(gatewayUrlRaw),
    enrollmentToken,
    credential,
    credentialFile,
    gitlabBaseUrl: parseBaseUrl(gitlabBaseUrlRaw),
    gitlabToken: firstText(env, ["GITLAB_TOKEN"]),
    connectorName: firstText(env, ["HEEDVANE_CONNECTOR_NAME", "CONNECTOR_NAME"]),
    capabilityProfile: parseProfile(firstText(env, ["HEEDVANE_CAPABILITY_PROFILE", "CAPABILITY_PROFILE"])),
    proxyUrl: firstText(env, ["HEEDVANE_PROXY_URL", "HTTPS_PROXY", "https_proxy"]),
    gatewayCaFile: firstText(env, ["HEEDVANE_GATEWAY_CA_FILE"]),
    gitlabCaFile: firstText(env, ["GITLAB_CA_FILE"]),
    hubAllowlistPublicKeyFile,
    webhookListenHost: firstText(env, ["WEBHOOK_LISTEN_HOST"]) ?? DEFAULT_WEBHOOK_LISTEN_HOST,
    webhookListenPort: parsePort(firstText(env, ["WEBHOOK_LISTEN_PORT"])),
    webhookSecret: firstText(env, ["WEBHOOK_SECRET"]),
    advertiseHost: firstText(env, ["CONNECTOR_ADVERTISE_HOST"]),
    requestTimeoutMs: parseTimeout(firstText(env, ["GITLAB_REQUEST_TIMEOUT_MS"])),
  };
}
