# connector - customer-run code-host connector

> Last updated: 2026-08-07

The customer-side half of the connector tunnel: one outbound WebSocket to the api's
connector gateway, serving the signed-allowlist subset of GitLab traffic plus local
webhook intake. Operator surface (env, docker, failure behavior): [`README.md`](README.md).
Wire contract: [`@heedvane/connector-protocol`](../../packages/connector-protocol/AGENTS.md).

## Constraints that are load-bearing today

- **The connector is a pipe.** Nothing logs or persists bodies, payloads, header
  values, or credentials. The audit log (`src/audit-log.ts`) is metadata only, and the
  handler and listener tests assert no body material leaks into it.
- **Fail closed, then tell the truth.** Allowlist signature failures, enrollment
  refusals, credential-invalid responses, and allowlist-key fetch failures are terminal
  exits with the peer's real message (and, for the key fetch, the exact URL tried).
  Everything else reconnects with capped backoff and resumes on the persisted
  credential, never the spent enrollment token.
- **The allowlist key is fetched, never skipped.** `HUB_ALLOWLIST_PUBLIC_KEY_FILE` is
  optional; without it, boot fetches the key from `<gateway origin>/connector/allowlist-public-key`
  through the same proxy and gateway CA as the tunnel (`src/allowlist-key.ts`). Any
  weakening toward "verify later" breaks the confused-deputy contract.
- **The env names the hub emits win.** `dockerRunCommand` on the web side writes
  `HEEDVANE_GATEWAY_URL`, `HEEDVANE_CONNECTOR_NAME`, and `HEEDVANE_CAPABILITY_PROFILE`;
  `src/config.ts` accepts those exact names and keeps short aliases for hand-rolled
  deployments. Renaming one side breaks onboarding.
- **Runtime dependencies stay at two** (`ws` and the workspace protocol package): every
  dependency is code in the customer's network. The CONNECT proxy agent and the GitLab
  HTTP client are hand-rolled on core modules for that reason.
- **Two trust stores, never merged.** `HEEDVANE_GATEWAY_CA_FILE` covers the tunnel
  (egress proxy re-signing), `GITLAB_CA_FILE` covers the customer's GitLab.
- **Byte streams (protocol 2) pipe, never terminate.** `src/byte-stream.ts` accepts a
  target matching the configured GitLab route (GITLAB_BASE_URL) OR the instance
  identity (instanceBaseUrl from the server-hello; identity and route are separate by
  design), dials ONLY the route, passes bytes opaquely (TLS is the endpoints'
  business), honors the window in both directions (flow-control-violated is terminal),
  and kills every stream when its tunnel dies.
- **Authenticated HTTP streams (protocol 3) keep credentials local.**
  `src/gitlab-http-stream.ts` terminates GitLab TLS inside the customer's network,
  applies the signed allowlist and local capability profile, strips caller auth,
  injects `GITLAB_TOKEN`, and streams only smart-HTTP upload-pack traffic. Bodies and
  tokens never enter connector logs.
- **The customer connector requires GitLab 19+.** Boot authenticates
  `GET /api/v4/version` before enrollment and refuses an unreadable version or a
  major below 19. Local webhooks require the GitLab 19 `whsec_` Standard Webhooks
  HMAC; plaintext `X-Gitlab-Token` and signature-presence fallbacks stay absent.
- Tests are `node:test` via `tsx` against in-process stub servers (stub gateway, stub
  GitLab, stub CONNECT proxy): `pnpm --filter @heedvane/connector test`.
