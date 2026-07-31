// Forwards one allowlisted request to the local GitLab over core http/https. Core
// modules rather than fetch because the customer GitLab trust store (GITLAB_CA_FILE)
// needs a per-connection `ca`, which the global fetch cannot take without another
// dependency. The connector is a pipe: bytes and status travel unchanged, only
// hop-by-hop framing is rebuilt and the credential is injected.

import { request as httpRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";

import type { HttpMethod, QueryParam } from "@heedvane/connector-protocol";

export class UpstreamTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamTimeoutError";
  }
}

export class UpstreamUnreachableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpstreamUnreachableError";
  }
}

export interface GitLabForwardRequest {
  readonly method: HttpMethod;
  readonly path: string;
  readonly query: readonly QueryParam[];
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBase64?: string;
  readonly credential: string;
}

export interface GitLabForwardResult {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly bodyBase64?: string;
}

export interface ForwarderOptions {
  readonly baseUrl: string;
  readonly timeoutMs: number;
  readonly ca?: Buffer;
}

const PRIVATE_TOKEN_HEADER = "private-token";
const HTTPS_PROTOCOL = "https:";

// Hop-by-hop framing and stale routing headers are rebuilt per hop; anything else the
// hub sent (accept, content-type, its own tracing) travels unchanged.
const STRIPPED_REQUEST_HEADERS = new Set([
  "host",
  "connection",
  "content-length",
  "transfer-encoding",
  "upgrade",
  "keep-alive",
  "proxy-authorization",
  "proxy-authenticate",
  "te",
  "trailer",
  "trailers",
  PRIVATE_TOKEN_HEADER,
]);

const STRIPPED_RESPONSE_HEADERS = new Set([
  "connection",
  "content-length",
  "transfer-encoding",
  "keep-alive",
  "upgrade",
]);

function encodeQuery(query: readonly QueryParam[]): string {
  if (query.length === 0) return "";
  const pairs = query.map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`);
  return `?${pairs.join("&")}`;
}

function forwardHeaders(request: GitLabForwardRequest, bodyLength: number): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(request.headers)) {
    if (STRIPPED_REQUEST_HEADERS.has(name.toLowerCase())) continue;
    headers[name] = value;
  }
  headers["PRIVATE-TOKEN"] = request.credential;
  headers["content-length"] = String(bodyLength);
  return headers;
}

function responseHeaders(message: IncomingMessage): Record<string, string> {
  const headers: Record<string, string> = {};
  for (const [name, value] of Object.entries(message.headers)) {
    if (value === undefined || STRIPPED_RESPONSE_HEADERS.has(name)) continue;
    headers[name] = Array.isArray(value) ? value.join(", ") : value;
  }
  return headers;
}

function collectBody(message: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    message.on("data", (chunk: Buffer) => chunks.push(chunk));
    message.on("end", () => resolve(Buffer.concat(chunks)));
    message.on("error", reject);
  });
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export async function forwardToGitLab(
  request: GitLabForwardRequest,
  options: ForwarderOptions,
): Promise<GitLabForwardResult> {
  const baseUrl = new URL(options.baseUrl);
  const body = request.bodyBase64 === undefined ? Buffer.alloc(0) : Buffer.from(request.bodyBase64, "base64");
  const requestOptions: RequestOptions = {
    hostname: baseUrl.hostname,
    port: baseUrl.port || (baseUrl.protocol === HTTPS_PROTOCOL ? 443 : 80),
    method: request.method,
    path: `${baseUrl.pathname === "/" ? "" : baseUrl.pathname}${request.path}${encodeQuery(request.query)}`,
    headers: forwardHeaders(request, body.length),
    timeout: options.timeoutMs,
    ...(options.ca !== undefined ? { ca: options.ca } : {}),
  };
  const transport = baseUrl.protocol === HTTPS_PROTOCOL ? httpsRequest : httpRequest;
  return await new Promise<GitLabForwardResult>((resolve, reject) => {
    const upstream = transport(requestOptions, (message) => {
      void collectBody(message).then((responseBody) => {
        resolve({
          status: message.statusCode ?? 502,
          headers: responseHeaders(message),
          ...(responseBody.length > 0 ? { bodyBase64: responseBody.toString("base64") } : {}),
        });
      }, (error: unknown) => {
        // A body read failure after the response started is an upstream transport
        // failure; the hub hears the real reason, not a timeout.
        reject(new UpstreamUnreachableError(`failed reading the response body from the code host: ${errorMessage(error)}`));
      });
    });
    upstream.on("timeout", () => {
      upstream.destroy();
      reject(new UpstreamTimeoutError(
        `the code host at ${options.baseUrl} did not answer ${request.method} ${request.path} within ${options.timeoutMs}ms`,
      ));
    });
    upstream.on("error", (error: Error) => {
      reject(new UpstreamUnreachableError(
        `the code host at ${options.baseUrl} could not be reached for ${request.method} ${request.path}: ${error.message}`,
      ));
    });
    if (body.length > 0) upstream.write(body);
    upstream.end();
  });
}
