// Boot-time fetch of the hub's allowlist public key when HUB_ALLOWLIST_PUBLIC_KEY_FILE
// is not set. The connector never serves an allowlist it cannot verify, so a failed or
// malformed fetch is a hard boot error naming the exact URL tried; it is never silently
// skipped. The fetch rides the same egress settings as the tunnel: HEEDVANE_PROXY_URL
// (CONNECT) and the HEEDVANE_GATEWAY_CA_FILE trust store.

import { createPublicKey, type KeyObject } from "node:crypto";
import { request as httpRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";

import { ConnectProxyAgent } from "./proxy-agent.js";

export class AllowlistKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AllowlistKeyError";
  }
}

const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_KEY_BYTES = 65_536;

/** The hub serves the key beside the gateway endpoint: ws(s) becomes http(s) and the
 *  /connector-gateway path becomes /connector/allowlist-public-key. */
export function allowlistKeyUrl(gatewayUrl: string): string {
  const url = new URL(gatewayUrl.replace(/^ws:\/\//, "http://").replace(/^wss:\/\//, "https://"));
  url.pathname = url.pathname.replace(/\/connector-gateway\/?$/, "/connector/allowlist-public-key");
  url.search = "";
  url.hash = "";
  return url.toString();
}

export interface FetchAllowlistKeyInput {
  readonly keyUrl: string;
  readonly proxyUrl: string | null;
  readonly ca?: Buffer;
  readonly timeoutMs?: number;
}

function collectPem(message: IncomingMessage, keyUrl: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let received = 0;
    message.on("data", (chunk: Buffer) => {
      received += chunk.length;
      if (received > MAX_KEY_BYTES) {
        reject(new AllowlistKeyError(
          `the allowlist public key response from ${keyUrl} exceeds ${MAX_KEY_BYTES} bytes`,
        ));
        message.destroy();
        return;
      }
      chunks.push(chunk);
    });
    message.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    message.on("error", (error: Error) => {
      reject(new AllowlistKeyError(`failed reading the allowlist public key from ${keyUrl}: ${error.message}`));
    });
  });
}

function requestOptions(input: FetchAllowlistKeyInput, useTls: boolean): RequestOptions {
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (input.proxyUrl !== null) {
    return { method: "GET", timeout: timeoutMs, agent: new ConnectProxyAgent(input.proxyUrl, useTls, input.ca ?? null) };
  }
  return {
    method: "GET",
    timeout: timeoutMs,
    ...(input.ca !== undefined ? { ca: input.ca } : {}),
  };
}

export async function fetchAllowlistPublicKey(input: FetchAllowlistKeyInput): Promise<KeyObject> {
  const url = new URL(input.keyUrl);
  const useTls = url.protocol === "https:";
  const transport = useTls ? httpsRequest : httpRequest;
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pem = await new Promise<string>((resolve, reject) => {
    const request = transport(url, requestOptions(input, useTls), (message) => {
      if (message.statusCode !== 200) {
        message.resume();
        reject(new AllowlistKeyError(
          `the hub answered the allowlist public key request to ${input.keyUrl} with HTTP ${message.statusCode}`,
        ));
        return;
      }
      void collectPem(message, input.keyUrl).then(resolve, reject);
    });
    request.on("timeout", () => {
      request.destroy();
      reject(new AllowlistKeyError(
        `fetching the allowlist public key from ${input.keyUrl} timed out after ${timeoutMs}ms`,
      ));
    });
    request.on("error", (error: Error) => {
      reject(new AllowlistKeyError(`could not fetch the allowlist public key from ${input.keyUrl}: ${error.message}`));
    });
    request.end();
  });
  try {
    return createPublicKey(pem);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new AllowlistKeyError(`the key fetched from ${input.keyUrl} is not a usable PEM public key: ${reason}`);
  }
}
