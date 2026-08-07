# @heedvane/connector

> Last updated: 2026-08-04

The customer-run half of the Heedvane code-host connector. It runs inside the
customer's network, opens ONE outbound WebSocket tunnel to the Heedvane connector
gateway, and serves exactly the GitLab request shapes on the hub's signed allowlist,
bounded by a locally configured capability profile. Nothing inbound is opened on the
customer firewall except the local webhook listener their GitLab posts to. Governing
design: `code-host-connector-design-2026-07-24` (Heedvane monorepo, `docs/engineering/plans/`).
The wire contract lives in [`@heedvane/connector-protocol`](../../packages/connector-protocol/README.md);
this package implements the connector side and reuses the protocol's validators and
allowlist matchers rather than reimplementing them.

The connector is a pipe: it never logs or persists request or response bodies, webhook
payloads, or credentials. Its audit log (stdout, one JSON line per decision, prefixed
`[connector-audit]`) records which requests and deliveries were allowed or refused,
with reasons.

## Run with Docker (the normal path)

Pull the published multi-architecture image from GHCR:

```sh
docker pull ghcr.io/flowconai/heedvane-connector:0.2.2
```

The hub's enrollment dialog (`POST /api/code-hosts/gitlab/connector-enrollments` in the
UI) emits the exact `docker run` command for a connection, with these variables filled
in:

```sh
docker run --restart unless-stopped --name heedvane-connector \
  -v heedvane-connector-data:/var/lib/heedvane-connector \
  -e HEEDVANE_GATEWAY_URL=wss://api.heedvane.example/connector-gateway \
  -e HEEDVANE_ENROLLMENT_TOKEN=<single-use token> \
  -e HEEDVANE_CREDENTIAL_FILE=/var/lib/heedvane-connector/credential \
  -e GITLAB_BASE_URL=https://gitlab.example.com \
  -e GITLAB_TOKEN=<GitLab token with api scope> \
  -e "HEEDVANE_CONNECTOR_NAME=Zurich office" \
  -e HEEDVANE_CAPABILITY_PROFILE=read-only \
  -p 8080:8080 \
  ghcr.io/flowconai/heedvane-connector:0.2.2
```

First boot enrolls: the connector exchanges the single-use enrollment token for a
long-lived credential and persists it to `HEEDVANE_CREDENTIAL_FILE` (mounted volume,
written `0600`). Every later start resumes with that file. If the file is lost, the
restart fails truthfully and a fresh enrollment token must be issued in the hub UI;
the enrollment token itself cannot be replayed.

## Configuration (environment)

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `HEEDVANE_GATEWAY_URL` | yes | | ws(s) URL of the connector gateway. `HEEDVANE_CONNECTOR_GATEWAY_URL` is accepted as an alias. |
| `HEEDVANE_ENROLLMENT_TOKEN` | first boot | | Single-use enrollment token from the hub UI. |
| `HEEDVANE_CONNECTOR_CREDENTIAL` | restarts | | Long-lived credential, if not using the file below. |
| `HEEDVANE_CREDENTIAL_FILE` | recommended | `/var/lib/heedvane-connector/credential` in Docker | Path the credential is read from and persisted to. Mount its parent directory. Resolution order: env credential, then this file when it holds one, then the enrollment token. A persisted credential therefore wins over the still-configured consumed token on every restart, and a missing file on first boot simply means enroll. To force a fresh enrollment, delete the file. |
| `GITLAB_BASE_URL` | yes | | http(s) origin of the GitLab instance this connector serves. |
| `GITLAB_TOKEN` | yes | | Local API token used to verify the GitLab version at boot and injected into credential-less requests. The token never leaves the customer network. |
| `HEEDVANE_CONNECTOR_NAME` | no | | Display name reported to the hub (`CONNECTOR_NAME` alias). |
| `HEEDVANE_CAPABILITY_PROFILE` | no | `read-only` | `read-only` or `read-write` (`CAPABILITY_PROFILE` alias). The signed allowlist may only ever be a subset of this profile: anything outside it is refused with `profile-refused`. |
| `HUB_ALLOWLIST_PUBLIC_KEY_FILE` | no | fetched | Ed25519 public key (PEM) matching the gateway's signing key. When unset, the connector fetches it at boot from the hub at `<gateway origin>/connector/allowlist-public-key` (derived from `HEEDVANE_GATEWAY_URL`, through the same proxy and gateway CA settings as the tunnel) and logs the fetch. A fetch failure or a malformed PEM is a boot error naming the URL tried; verification is never skipped. Set the file only when the hub cannot be reached for the fetch. |
| `HEEDVANE_PROXY_URL` | no | | Outbound HTTP proxy for the tunnel (`http://user:pass@proxy:3128`), dialed with CONNECT. `HTTPS_PROXY`/`https_proxy` are honored as fallbacks. |
| `HEEDVANE_GATEWAY_CA_FILE` | no | | CA bundle (PEM) for the GATEWAY connection, for an egress proxy that re-signs TLS. |
| `GITLAB_CA_FILE` | no | | CA bundle (PEM) for the GitLab connection. Deliberately separate from the gateway CA: two trust stores, two knobs. |
| `WEBHOOK_LISTEN_HOST` / `WEBHOOK_LISTEN_PORT` | no | `0.0.0.0:8080` | Where the local webhook listener binds. |
| `WEBHOOK_SECRET` | for webhooks | | Connector-local webhook secret. GitLab 18.11 sends it as `X-Gitlab-Token`; GitLab 19+ uses it as a `whsec_` Standard Webhooks HMAC key. Without it the listener refuses every delivery. |
| `CONNECTOR_ADVERTISE_HOST` | no | OS hostname | Hostname used in the `webhookBaseUrl` reported to the hub; set it to the address the GitLab server uses to reach this connector. |
| `GITLAB_REQUEST_TIMEOUT_MS` | no | `25000` | Per-request budget to the local GitLab. Kept below the gateway's 30s so a slow GitLab reports `upstream-timeout` instead of a generic tunnel timeout. |

## Webhooks

Point the GitLab instance's webhook at `http://<connector-host>:<port>/webhooks/gitlab`
(the exact URL the connector reports as `webhookBaseUrl`). Verification happens locally
before anything crosses the tunnel:

- GitLab 18.11 (`X-Gitlab-Token`): the listener uses constant-time comparison and
  forwards the delivery as `verificationScheme: secret-token`.
- GitLab 19+ (`webhook-signature`): `WEBHOOK_SECRET` is the `whsec_` signing token.
  The listener verifies HMAC-SHA256 and the five-minute timestamp before forwarding
  the delivery as `verificationScheme: signing-token`.
- The authenticated `/api/v4/version` result selects exactly one scheme before
  enrollment. Header presence never changes it and there is no fallback.

The connector answers the local GitLab with 200 only after the gateway ack confirms the
hub queued the delivery; a hub refusal is mirrored with its real status, and a missing
ack inside 15s is a 504, so GitLab's own retry semantics stay truthful.

## Failure behavior an operator can rely on

- Consumed or expired enrollment token: the connector prints the hub's real refusal
  (unknown, expired, or already consumed) and exits non-zero. Issue a fresh token.
- Gateway or network down: reconnects forever with capped exponential backoff (1s
  doubling, 60s cap, jittered) and resumes with the persisted credential.
- Signed allowlist fails verification: terminal exit naming the key source (the
  configured `HUB_ALLOWLIST_PUBLIC_KEY_FILE` or the fetched URL), because serving an
  unverifiable allowlist is never correct. The same honesty covers the key fetch
  itself: a 404, timeout, or malformed PEM exits non-zero naming the URL tried.
- GitLab down vs refused vs timeout are distinct error codes on the tunnel
  (`upstream-unreachable`, `allowlist-refused`/`profile-refused`, `upstream-timeout`),
  so the hub's failure message routes to the right team.

## Development

```sh
pnpm install
pnpm --filter @heedvane/connector-protocol build   # the workspace dependency ships dist
pnpm --filter @heedvane/connector test             # node:test via tsx, in-process stubs
pnpm --filter @heedvane/connector build            # tsc to dist/
pnpm --filter @heedvane/connector dev              # tsx src/cli.ts against real env
```
