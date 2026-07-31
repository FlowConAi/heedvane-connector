// Outbound WebSocket dial options for the gateway, including the corporate egress
// proxy path. A network locked down enough to need this connector very often mandates
// a proxy for outbound traffic (docs/engineering/plans/code-host-connector-design-2026-07-24.md),
// so the tunnel must CONNECT through it. The proxy trust store
// (HEEDVANE_GATEWAY_CA_FILE, for a re-signing egress proxy) is deliberately separate
// from the GitLab trust store (GITLAB_CA_FILE): two different CAs, two knobs.

import { Agent as HttpAgent, type ClientRequest, type ClientRequestArgs } from "node:http";
import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import type { Duplex } from "node:stream";

import type { ClientOptions } from "ws";

export interface GatewaySocketInput {
  readonly gatewayUrl: string;
  readonly proxyUrl: string | null;
  readonly ca: Buffer | null;
}

const CONNECT_TIMEOUT_MS = 10_000;

function proxyAuthorization(proxy: URL): string | null {
  if (proxy.username === "" && proxy.password === "") return null;
  const user = decodeURIComponent(proxy.username);
  const password = decodeURIComponent(proxy.password);
  return `Basic ${Buffer.from(`${user}:${password}`, "utf8").toString("base64")}`;
}

/** Read the proxy's answer to CONNECT up to the header terminator. */
function awaitConnectResponse(socket: Socket, onStatus: (statusLine: string, rest: Buffer) => void): void {
  let buffer = Buffer.alloc(0);
  socket.on("data", (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    const headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd === -1) return;
    const head = buffer.subarray(0, headerEnd).toString("utf8");
    socket.removeAllListeners("data");
    onStatus(head.split("\r\n")[0] ?? "", buffer.subarray(headerEnd + 4));
  });
}

interface ConnectTarget {
  readonly proxySocket: Socket;
  readonly host: string;
  readonly port: number;
  readonly options: ClientRequestArgs;
  readonly callback: (error: Error | null, socket?: Duplex) => void;
}

/** An HTTP(S) agent that reaches its target through a corporate CONNECT proxy. Used by
 *  the tunnel WebSocket and by the boot-time allowlist key fetch. */
export class ConnectProxyAgent extends HttpAgent {
  // Both exist on Agent at runtime but are absent from @types/node's declaration.
  public declare protocol: string;
  public declare defaultPort: number;

  private readonly proxy: URL;
  private readonly targetTls: boolean;
  private readonly targetCa: Buffer | null;

  constructor(proxyUrl: string, targetTls: boolean, targetCa: Buffer | null) {
    super();
    this.proxy = new URL(proxyUrl);
    this.targetTls = targetTls;
    this.targetCa = targetCa;
    // The HTTP client validates the agent's declared protocol against the request, so
    // the agent must present the TARGET's scheme, not the proxy's.
    this.protocol = targetTls ? "https:" : "http:";
    this.defaultPort = targetTls ? 443 : 80;
  }

  /** createSocket rather than createConnection: it is the async seam the base agent
   *  dispatches to, so the CONNECT handshake can complete before the HTTP layer
   *  touches the socket. */
  public createSocket(
    _request: ClientRequest,
    options: ClientRequestArgs,
    callback: (error: Error | null, socket?: Duplex) => void,
  ): void {
    const host = options.host ?? "localhost";
    const port = Number(options.port ?? this.defaultPort);
    const proxySocket = netConnect({ host: this.proxy.hostname, port: Number(this.proxy.port || 8080) });
    proxySocket.setTimeout(CONNECT_TIMEOUT_MS);
    proxySocket.once("error", (error: Error) => callback(error));
    proxySocket.once("timeout", () => {
      proxySocket.destroy();
      callback(new Error(`the egress proxy at ${this.proxy.host} did not answer CONNECT within ${CONNECT_TIMEOUT_MS}ms`));
    });
    proxySocket.once("connect", () => {
      this.negotiateConnect({ proxySocket, host, port, options, callback });
    });
  }

  private negotiateConnect(target: ConnectTarget): void {
    const { proxySocket, host, port, options, callback } = target;
    const authorization = proxyAuthorization(this.proxy);
    const lines = [`CONNECT ${host}:${port} HTTP/1.1`, `Host: ${host}:${port}`];
    if (authorization !== null) lines.push(`Proxy-Authorization: ${authorization}`);
    proxySocket.write(`${lines.join("\r\n")}\r\n\r\n`);
    awaitConnectResponse(proxySocket, (statusLine, rest) => {
      if (!/^HTTP\/\d(?:\.\d)?\s+2\d\d/.test(statusLine)) {
        proxySocket.destroy();
        callback(new Error(`the egress proxy refused CONNECT to ${host}:${port}: ${statusLine}`));
        return;
      }
      proxySocket.setTimeout(0);
      proxySocket.removeAllListeners("error");
      proxySocket.removeAllListeners("timeout");
      // Bytes the proxy flushed after its CONNECT headers belong to the target; hand
      // them back to the socket so neither the HTTP layer nor the TLS parser loses them.
      if (rest.length > 0) proxySocket.unshift(rest);
      if (!this.targetTls) {
        callback(null, proxySocket);
        return;
      }
      const servername = (options as { servername?: unknown }).servername;
      const tlsSocket = tlsConnect({
        socket: proxySocket,
        servername: typeof servername === "string" ? servername : host,
        ...(this.targetCa !== null ? { ca: this.targetCa } : {}),
      });
      tlsSocket.once("secureConnect", () => callback(null, tlsSocket));
      tlsSocket.once("error", (error: Error) => callback(error));
    });
  }
}

export function buildGatewaySocketOptions(input: GatewaySocketInput): ClientOptions {
  const targetTls = input.gatewayUrl.startsWith("wss://");
  if (input.proxyUrl !== null) {
    return { agent: new ConnectProxyAgent(input.proxyUrl, targetTls, input.ca) };
  }
  if (input.ca !== null) {
    return { ca: input.ca };
  }
  return {};
}
