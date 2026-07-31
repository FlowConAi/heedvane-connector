import assert from "node:assert/strict";
import { test } from "node:test";

import { ConfigError, loadConfig } from "./config.js";

const REQUIRED_ENV: Record<string, string> = {
  HEEDVANE_GATEWAY_URL: "wss://api.heedvane.example/connector-gateway",
  HEEDVANE_ENROLLMENT_TOKEN: "enroll-token-abc",
  GITLAB_BASE_URL: "https://gitlab.example.com",
};

function load(env: Record<string, string | undefined>): ReturnType<typeof loadConfig> {
  return loadConfig({ env, readCredentialFile: () => "credential-from-file" });
}

test("a minimal environment parses with the documented defaults", () => {
  const config = load({ ...REQUIRED_ENV });
  assert.equal(config.gatewayUrl, "wss://api.heedvane.example/connector-gateway");
  assert.equal(config.enrollmentToken, "enroll-token-abc");
  assert.equal(config.credential, null);
  assert.equal(config.gitlabBaseUrl, "https://gitlab.example.com");
  assert.equal(config.gitlabToken, null);
  assert.equal(config.capabilityProfile, "read-only");
  assert.equal(config.webhookListenHost, "0.0.0.0");
  assert.equal(config.webhookListenPort, 8080);
  assert.equal(config.proxyUrl, null);
});

test("the allowlist public key file is optional: unset parses as null so boot can fetch it", () => {
  const config = load({ ...REQUIRED_ENV });
  assert.equal(config.hubAllowlistPublicKeyFile, null);
  const withFile = load({ ...REQUIRED_ENV, HUB_ALLOWLIST_PUBLIC_KEY_FILE: "/run/heedvane/hub-public.pem" });
  assert.equal(withFile.hubAllowlistPublicKeyFile, "/run/heedvane/hub-public.pem");
});

test("the env names the hub's dockerRunCommand emits all work", () => {
  const config = load({
    ...REQUIRED_ENV,
    HEEDVANE_CONNECTOR_NAME: "Zurich office",
    HEEDVANE_CAPABILITY_PROFILE: "read-write",
  });
  assert.equal(config.connectorName, "Zurich office");
  assert.equal(config.capabilityProfile, "read-write");
});

test("the legacy alias names still parse", () => {
  const config = load({
    ...REQUIRED_ENV,
    HEEDVANE_GATEWAY_URL: undefined,
    HEEDVANE_CONNECTOR_GATEWAY_URL: "wss://gw.example/connector-gateway",
    CONNECTOR_NAME: "edge a",
    CAPABILITY_PROFILE: "read-write",
  });
  assert.equal(config.gatewayUrl, "wss://gw.example/connector-gateway");
  assert.equal(config.connectorName, "edge a");
  assert.equal(config.capabilityProfile, "read-write");
});

test("a missing gateway URL fails with the variable named", () => {
  assert.throws(
    () => load({ ...REQUIRED_ENV, HEEDVANE_GATEWAY_URL: undefined }),
    (error: unknown) => error instanceof ConfigError && /HEEDVANE_GATEWAY_URL/.test(error.message),
  );
});

test("a non-WebSocket gateway URL is refused", () => {
  assert.throws(
    () => load({ ...REQUIRED_ENV, HEEDVANE_GATEWAY_URL: "https://api.example/connector-gateway" }),
    /ws:\/\/|wss:\/\//,
  );
});

test("enrollment needs a token or a credential; both absent is an operator-readable error", () => {
  assert.throws(
    () => load({ ...REQUIRED_ENV, HEEDVANE_ENROLLMENT_TOKEN: undefined }),
    (error: unknown) =>
      error instanceof ConfigError
      && /HEEDVANE_ENROLLMENT_TOKEN/.test(error.message)
      && /HEEDVANE_CONNECTOR_CREDENTIAL/.test(error.message),
  );
});

test("a configured credential resumes instead of enrolling", () => {
  const config = load({
    ...REQUIRED_ENV,
    HEEDVANE_ENROLLMENT_TOKEN: undefined,
    HEEDVANE_CONNECTOR_CREDENTIAL: "cred-123",
  });
  assert.equal(config.credential, "cred-123");
  assert.equal(config.enrollmentToken, null);
});

test("the credential is read from the credential file when no env credential is set", () => {
  const config = load({
    ...REQUIRED_ENV,
    HEEDVANE_ENROLLMENT_TOKEN: undefined,
    HEEDVANE_CREDENTIAL_FILE: "/run/heedvane/credential",
  });
  assert.equal(config.credential, "credential-from-file");
});

test("first boot: an enrollment token with a MISSING credential file enrolls instead of crashing", () => {
  const config = loadConfig({
    env: { ...REQUIRED_ENV, HEEDVANE_CREDENTIAL_FILE: "/var/lib/heedvane-connector/credential" },
    readCredentialFile: () => {
      const error = new Error("ENOENT: no such file or directory") as NodeJS.ErrnoException;
      error.code = "ENOENT";
      throw error;
    },
  });
  assert.equal(config.credential, null);
  assert.equal(config.enrollmentToken, "enroll-token-abc");
});

test("restart: a persisted credential file wins over the still-configured, now-consumed token", () => {
  const config = loadConfig({
    env: { ...REQUIRED_ENV, HEEDVANE_CREDENTIAL_FILE: "/var/lib/heedvane-connector/credential" },
    readCredentialFile: () => "credential-from-file",
  });
  assert.equal(config.credential, "credential-from-file");
  assert.equal(config.enrollmentToken, "enroll-token-abc");
});

test("no token and a missing credential file is the operator-readable neither-configured error", () => {
  assert.throws(
    () => loadConfig({
      env: { ...REQUIRED_ENV, HEEDVANE_ENROLLMENT_TOKEN: undefined, HEEDVANE_CREDENTIAL_FILE: "/var/lib/heedvane-connector/credential" },
      readCredentialFile: () => {
        const error = new Error("ENOENT: no such file or directory") as NodeJS.ErrnoException;
        error.code = "ENOENT";
        throw error;
      },
    }),
    (error: unknown) =>
      error instanceof ConfigError
      && /HEEDVANE_ENROLLMENT_TOKEN/.test(error.message)
      && /HEEDVANE_CONNECTOR_CREDENTIAL/.test(error.message)
      && !/ENOENT/.test(error.message),
  );
});

test("a token with an UNREADABLE credential file still enrolls; the file is overwritten after enroll", () => {
  const config = loadConfig({
    env: { ...REQUIRED_ENV, HEEDVANE_CREDENTIAL_FILE: "/var/lib/heedvane-connector/credential" },
    readCredentialFile: () => {
      const error = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
      error.code = "EACCES";
      throw error;
    },
  });
  assert.equal(config.credential, null);
  assert.equal(config.enrollmentToken, "enroll-token-abc");
});

test("an unreadable credential file with NO token is a named config error, not a raw crash", () => {
  assert.throws(
    () => loadConfig({
      env: { ...REQUIRED_ENV, HEEDVANE_ENROLLMENT_TOKEN: undefined, HEEDVANE_CREDENTIAL_FILE: "/var/lib/heedvane-connector/credential" },
      readCredentialFile: () => {
        const error = new Error("EACCES: permission denied") as NodeJS.ErrnoException;
        error.code = "EACCES";
        throw error;
      },
    }),
    (error: unknown) =>
      error instanceof ConfigError
      && /HEEDVANE_CREDENTIAL_FILE/.test(error.message)
      && /permission denied/.test(error.message),
  );
});

test("an invalid capability profile names the valid values", () => {
  assert.throws(
    () => load({ ...REQUIRED_ENV, HEEDVANE_CAPABILITY_PROFILE: "admin" }),
    /read-only.*read-write|read-write.*read-only/,
  );
});

test("proxy and trust-store settings parse", () => {
  const config = load({
    ...REQUIRED_ENV,
    HEEDVANE_PROXY_URL: "http://user:pass@proxy.example:3128",
    HEEDVANE_GATEWAY_CA_FILE: "/run/heedvane/egress-ca.pem",
    GITLAB_CA_FILE: "/run/heedvane/gitlab-ca.pem",
    GITLAB_TOKEN: "glpat-local",
    WEBHOOK_LISTEN_HOST: "127.0.0.1",
    WEBHOOK_LISTEN_PORT: "9090",
    WEBHOOK_SECRET: "hook-secret",
    CONNECTOR_ADVERTISE_HOST: "connector.internal",
  });
  assert.equal(config.proxyUrl, "http://user:pass@proxy.example:3128");
  assert.equal(config.gatewayCaFile, "/run/heedvane/egress-ca.pem");
  assert.equal(config.gitlabCaFile, "/run/heedvane/gitlab-ca.pem");
  assert.equal(config.gitlabToken, "glpat-local");
  assert.equal(config.webhookListenHost, "127.0.0.1");
  assert.equal(config.webhookListenPort, 9090);
  assert.equal(config.webhookSecret, "hook-secret");
  assert.equal(config.advertiseHost, "connector.internal");
});

test("HTTPS_PROXY is honored as the proxy fallback", () => {
  const config = load({ ...REQUIRED_ENV, HTTPS_PROXY: "http://proxy.example:8080" });
  assert.equal(config.proxyUrl, "http://proxy.example:8080");
});

test("a malformed webhook listen port is refused", () => {
  assert.throws(
    () => load({ ...REQUIRED_ENV, WEBHOOK_LISTEN_PORT: "not-a-port" }),
    /WEBHOOK_LISTEN_PORT/,
  );
});
