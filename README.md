# Heedvane code-host connector

The customer-run half of [Heedvane](https://github.com/FlowConAi/heedvane)'s
self-managed code-host support. It runs **inside your network**, opens **one
outbound WebSocket tunnel** to the Heedvane connector gateway, and serves exactly
the GitLab request shapes on the hub's signed allowlist — bounded by a capability
profile you configure locally. Nothing inbound is opened on your firewall except
the local webhook listener your GitLab posts to.

This is why it works for instances behind a VPN or a source-address allowlist:
all connectivity is outbound from your side.

## Why you can run this

- **Allowlisted, not a proxy.** The connector refuses every request shape that is
  not on the hub's Ed25519-signed allowlist (verified at boot, never skipped) and
  outside your locally declared capability profile (`read-only` or `read-write`).
- **It is a pipe.** It never logs or persists request/response bodies, webhook
  payloads, or credentials. Its audit log (stdout, one JSON line per decision)
  records which requests were allowed or refused, with reasons — and nothing else.
- **No push, ever.** `git-receive-pack` is structurally absent from the allowlist.
- **Credential can stay with you.** Requests may arrive credential-less, in which
  case the connector injects a token from its own local config. Your GitLab token
  never has to leave your network.

The full configuration reference and failure behavior: [`apps/connector/README.md`](apps/connector/README.md).
The wire contract: [`packages/connector-protocol/README.md`](packages/connector-protocol/README.md).

## Quickstart

```sh
docker pull ghcr.io/flowconai/heedvane-connector:0.2.1
```

Heedvane's enrollment dialog emits the exact `docker run` command for your
connection with the variables filled in:

```sh
docker run --restart unless-stopped --name heedvane-connector \
  -v heedvane-connector-data:/var/lib/heedvane-connector \
  -e HEEDVANE_GATEWAY_URL=wss://api.heedvane.example/connector-gateway \
  -e HEEDVANE_ENROLLMENT_TOKEN=<single-use token> \
  -e HEEDVANE_CREDENTIAL_FILE=/var/lib/heedvane-connector/credential \
  -e GITLAB_BASE_URL=https://gitlab.example.com \
  -e GITLAB_TOKEN=<GitLab token with api scope> \
  -e HEEDVANE_CAPABILITY_PROFILE=read-only \
  -p 8080:8080 \
  ghcr.io/flowconai/heedvane-connector:0.2.1
```

First boot exchanges the single-use enrollment token for a long-lived credential
(persisted to the mounted credential file); every later start resumes with it.

## Repository layout

- `apps/connector` — the connector itself (Docker image, CLI, tests)
- `packages/connector-protocol` — the wire contract shared with the Heedvane
  gateway: framed JSON over one mutually authenticated WebSocket, the signed
  request allowlist, and capability profiles

## Development

```sh
pnpm install
pnpm build   # protocol package, then connector
pnpm test    # node:test suites for both packages
```

## License

[Apache-2.0](LICENSE)
