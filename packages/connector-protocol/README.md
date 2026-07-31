# @heedvane/connector-protocol

> Last updated: 2026-07-29

Wire contract shared by the connector gateway (hub side) and the customer-run code-host
connector. One mutually authenticated WebSocket carries framed JSON in both directions;
this package owns the frame shapes, their runtime validators, the request allowlist
model with capability profiles, and the Ed25519 signing of server-supplied allowlists.
Governing design: `code-host-connector-design-2026-07-24` (Heedvane monorepo, `docs/engineering/plans/`).

Zero runtime dependencies. Everything is hand-rolled TypeScript compiled with `tsc`.

## Build and test

Tests are TypeScript compiled to `dist/` and run with `node --test` on the compiled
output, the same compile-then-test pattern as `apps/api`:

```sh
pnpm --filter @heedvane/connector-protocol test
```

This runs `tsc -p tsconfig.json` and then `node --test` over `dist/frames.test.js` and
`dist/allowlist.test.js`. Consumers import the compiled entry (`dist/index.js` with
`dist/index.d.ts` types), so the package works for both the `tsc`-built api and
`tsx`-run tooling.

## Frames (`src/frames.ts`)

All frames are JSON objects discriminated by `type`. `encodeFrame`/`decodeFrame`
serialize and parse; `decodeFrame` throws `FrameValidationError` naming the frame type
and the failed field. Per-type `is*Frame` guards narrow already-parsed values.

| type | direction | purpose |
|---|---|---|
| `client-hello` | connector to gateway | Opens the tunnel. Enroll: `enrollmentToken` (single-use). Resume: `credential` (long-lived). Exactly one of the two must be present. |
| `server-hello` | gateway to connector | Tunnel accepted. On enrollment a fresh long-lived `credential` is returned; on resume the field is absent. Carries `credentialRotatesAt`, `allowlistVersion` + `allowlistSignature` announcement, `heartbeatIntervalMs`, and `minSupportedConnectorVersion`. |
| `allowlist` | gateway to connector | The signed allowlist document: `version`, `signature`, `entries`. Verified with `verifySignedAllowlist` before use. |
| `request` | gateway to connector | One code-host request on a stream. `credential` present means the hub holds the token (option i); absent means the connector injects it locally (option ii). Both shapes are valid from protocol version 1. |
| `response` | connector to gateway | Terminal success for a `requestId`: status, headers, optional base64 body. |
| `stream-error` | connector to gateway | Terminal failure for a stream. `requestId` is present on request/response streams and absent on raw byte streams. Codes: request failures (`allowlist-refused`, `profile-refused`, `credential-unavailable`, `upstream-unreachable`, `upstream-timeout`) and byte-stream failures (`target-refused`, `connect-refused`, `connect-timeout`, `upstream-reset`, `flow-control-violated`). |
| `webhook` | connector to gateway | A code-host webhook delivery. `verificationScheme` is `secret-token` (classic X-Gitlab-Token comparison, the only scheme GitLab before 19 offers) or `signing-token` (GitLab 19+). Headers travel unaltered so the hub can verify. |
| `stream-open` | gateway to connector | Opens a raw bidirectional byte stream to `target: {host, port}` inside the customer network. Only the gateway opens streams. |
| `stream-open-ack` | connector to gateway | Open result. `ok: true` carries no `code`/`message`; `ok: false` requires both, with `code` from the shared stream-error set. |
| `stream-data` | both | Stream payload as base64, decoded length capped at `MAX_STREAM_DATA_CHUNK_BYTES`. |
| `stream-window` | both | Additive flow-control credit in bytes. A sender must not have more unacked bytes in flight than its current credit. |
| `stream-close` | both | Directional half-close: the sender will send no more `stream-data` on this stream. Optional `reason` is `done` or `reset`. |
| `ping` / `pong` | both | Liveness; `pong` echoes the `ping` nonce. |
| `error` | gateway to connector | Connection-level refusal (`enrollment-failed`, `credential-invalid`, `protocol-version-unsupported`, `connector-version-unsupported`, `frame-invalid`). A version refusal message names both the actual version and the floor. |

Protocol constants: `PROTOCOL_VERSION = 2`, `MIN_SUPPORTED_CONNECTOR_VERSION`,
`DEFAULT_STREAM_WINDOW_BYTES` (256 KiB), `MAX_STREAM_DATA_CHUNK_BYTES` (64 KiB).

Why version 2: the byte-stream frames below are additive on paper, but a version 1 peer
rejects unknown frame types rather than ignoring them, so a gateway speaking streams to
a version 1 connector would break its tunnel. The version is therefore the stream
capability signal: peers that understand streams advertise 2, and a mismatch is refused
at hello with both numbers named. While the version check is strict equality, hub and
connector must upgrade together.

Version skew: validators fully check every known field but never strip unknown fields,
because connector and gateway ship independently. Unknown frame types are rejected with
the type named. `query` is an ordered list of `[name, value]` pairs (decoded names), not
an object, because GitLab relies on repeated names such as `refs[]`.

## Byte streams (protocol 2)

Control traffic (request/response, webhooks) and bulk traffic (git clone) share the one
WebSocket. Raw bytes travel on multiplexed streams so a large clone cannot stall control
frames behind it:

1. **Open.** The gateway sends `stream-open` with `target: {host, port}`. The connector
   dials the target inside the customer network and answers `stream-open-ack`. Only the
   gateway opens streams.
2. **Data and window, both directions.** Payloads travel as `stream-data` chunks.
   Each direction starts with `DEFAULT_STREAM_WINDOW_BYTES` of send credit; the receiver
   tops it up with `stream-window` as it consumes, and a sender must not exceed its
   current credit. This is the per-stream flow control the transport section of the
   design calls for: one stream's backlog can never consume the tunnel's whole capacity.
3. **Close.** `stream-close` is a directional half-close (the sender is done sending),
   so protocols that half-close a TCP write side map cleanly. The stream is fully closed
   when both directions have closed; a `stream-error` ends it immediately in both.

Bulk isolation has two parts, because a WebSocket message is the unit the tunnel cannot
preempt: the window bounds how far one stream can run ahead, and
`MAX_STREAM_DATA_CHUNK_BYTES` bounds how long one message occupies the tunnel, so
webhook and request/response frames never wait behind more than one bulk chunk.

## Allowlist (`src/allowlist.ts`)

The connector is not a confused deputy: it forwards only enumerated request shapes.
An `AllowlistEntry` is `{ methods, pathPattern, allowedQueryParams }`. Path patterns
match segment by segment; `:name` matches exactly one non-empty segment (so URL-encoded
ids such as `group%2Fproject` match), and a param may carry a literal suffix
(`:project.git` matches `widget.git`). Query filtering is fail-closed on decoded
parameter names: every name in the request must be listed. Values are unrestricted
except for smart-HTTP discovery, where `service` must occur exactly once with the
value `git-upload-pack`.

`SEED_ALLOWLIST` mirrors the hub's actual GitLab call set
(`apps/web/src/lib/code-host/gitlab/`): the design doc's table plus the reads the review
and activity paths also make (branch list/read, single commit, note list, discussion
list, note create). Each entry carries one capability (reads and writes are separate
entries) so a capability profile can refuse a write without touching the matching read.

`matchesAllowlist(entries, request)` returns the matching entry or `null`, where
`request` is `{ method, path, query }`.

Capability profiles (`profilePermits(profile, entry)`):

- `read-write` permits every valid entry.
- `read-only` permits entries whose methods are all safe (GET/HEAD) plus the
  git-upload-pack POST, because clone is a read even though smart HTTP fetch uses POST.
  It refuses hook mutations and every merge-request write (discussions and notes POSTs).
- No profile ever permits a receive-pack entry.

`git-receive-pack` is structurally absent, not merely unimplemented: document validation
rejects it, `matchesAllowlist` never matches it, and `profilePermits` refuses it, so a
server bug or forged document cannot open push access.

Signing: `canonicalizeAllowlist` produces an injective canonical string from the
version and each complete entry. Object keys, entries, and the two set-valued contract
fields are sorted. Unknown extension fields remain covered by the signature without
making older connectors reject them, and unknown array ordering stays significant.
`signAllowlist`/`verifyAllowlistSignature` use Ed25519 via `node:crypto`.
`verifySignedAllowlist` is the connector's acceptance path: entries are validated before
the signature is trusted, so a valid signature cannot legitimize a forbidden document.
The connector additionally refuses any entry outside its locally configured capability
profile (`profilePermits`), which keeps the server-supplied allowlist a subset of what
the customer permits.

## Known limitations

- Git smart-HTTP entries match a single-segment `:namespace`. Nested groups
  (`group/sub/project.git`) do not match; extending the pattern language for multi-
  segment namespaces is a protocol decision, not something to patch locally in a matcher.
- `RequestFrame`/`ResponseFrame` carry whole bodies as base64. Bulk bytes belong on
  byte streams; large payloads are out of scope for request/response frames.
