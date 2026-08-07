import { forwardToGitLab } from "./gitlab-forwarder.js";
import type { WebhookVerificationScheme } from "@heedvane/connector-protocol";

export const MIN_SUPPORTED_GITLAB_MAJOR = 18;
export const MIN_SUPPORTED_GITLAB_MINOR = 11;
const SIGNING_TOKEN_MIN_GITLAB_MAJOR = 19;

export class GitLabVersionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GitLabVersionError";
  }
}

export function parseGitLabMajorVersion(version: string): number {
  const majorText = version.split(".", 1)[0];
  const major = Number(majorText);
  if (majorText === undefined || majorText.length === 0 || !Number.isInteger(major) || major < 0) {
    throw new GitLabVersionError(`GitLab reported version "${version}", which did not contain a numeric major version.`);
  }
  return major;
}

export function requireSupportedGitLabVersion(version: string): void {
  const major = parseGitLabMajorVersion(version);
  const minorText = version.split(".", 2)[1];
  const minor = Number(minorText);
  if (minorText === undefined || !Number.isInteger(minor) || minor < 0) {
    throw new GitLabVersionError(`GitLab reported version "${version}", which did not contain a numeric minor version.`);
  }
  if (major < MIN_SUPPORTED_GITLAB_MAJOR || (major === MIN_SUPPORTED_GITLAB_MAJOR && minor < MIN_SUPPORTED_GITLAB_MINOR)) {
    throw new GitLabVersionError(
      `GitLab ${version} is unsupported; heedvane-connector requires GitLab ${MIN_SUPPORTED_GITLAB_MAJOR}.${MIN_SUPPORTED_GITLAB_MINOR} or newer.`,
    );
  }
}

export function webhookVerificationSchemeForGitLabVersion(version: string): WebhookVerificationScheme {
  requireSupportedGitLabVersion(version);
  return parseGitLabMajorVersion(version) >= SIGNING_TOKEN_MIN_GITLAB_MAJOR
    ? "signing-token"
    : "secret-token";
}

interface VerifyGitLabVersionInput {
  readonly baseUrl: string;
  readonly token: string;
  readonly timeoutMs: number;
  readonly ca?: Buffer;
}

export async function verifyGitLabVersion(input: VerifyGitLabVersionInput): Promise<string> {
  const response = await forwardToGitLab(
    {
      method: "GET",
      path: "/api/v4/version",
      query: [],
      headers: { accept: "application/json" },
      credential: input.token,
    },
    {
      baseUrl: input.baseUrl,
      timeoutMs: input.timeoutMs,
      ...(input.ca !== undefined ? { ca: input.ca } : {}),
    },
  );
  if (response.status < 200 || response.status >= 300) {
    throw new GitLabVersionError(
      `GitLab at ${input.baseUrl} answered HTTP ${response.status} to GET /api/v4/version. Check GITLAB_TOKEN and GitLab availability.`,
    );
  }
  if (response.bodyBase64 === undefined) {
    throw new GitLabVersionError(`GitLab at ${input.baseUrl} returned an empty version response.`);
  }
  let body: unknown;
  try {
    body = JSON.parse(Buffer.from(response.bodyBase64, "base64").toString("utf8"));
  } catch {
    throw new GitLabVersionError(`GitLab at ${input.baseUrl} returned a non-JSON version response.`);
  }
  if (typeof body !== "object" || body === null || !("version" in body) || typeof body.version !== "string") {
    throw new GitLabVersionError(`GitLab at ${input.baseUrl} returned a version response without a string version field.`);
  }
  requireSupportedGitLabVersion(body.version);
  return body.version;
}
