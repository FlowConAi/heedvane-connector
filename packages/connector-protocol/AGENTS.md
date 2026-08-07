# connector-protocol - connector wire contract

> Last updated: 2026-08-07

Framed JSON protocol over the single mutually authenticated WebSocket between the
connector gateway and the customer-run code-host connector, plus the signed request
allowlist and capability profiles. Frame and allowlist semantics: [`README.md`](README.md).
Governing design: `code-host-connector-design-2026-07-24` (Heedvane monorepo, `docs/engineering/plans/`).

## Constraints that are load-bearing today

- **Zero runtime dependencies, hand-rolled validators.** Both sides of the tunnel embed
  this package; a dependency here is a dependency in the customer network.
- **Unknown fields are tolerated, unknown frame types are not.** Connector and gateway
  ship independently, so validators never strip fields they do not know. Removing that
  tolerance is a protocol break.
- **`RequestFrame.credential` presence names the credential owner.** A present value is
  hub-held; an absent value means the customer connector injects its local credential.
  Both shapes stay valid because the direct and connector paths are both current.
- **`PROTOCOL_VERSION` is the stream-capability signal.** Version 1 peers reject unknown
  frame types rather than ignore them, so byte streams (open/ack/data/close/window) are
  version 2. Authenticated HTTP streams are version 3. Bump the version whenever a new
  frame cannot be silently dropped by old peers, and say why in the README.
- **Byte-stream flow control is a contract, not a hint.** Send credit starts at
  `DEFAULT_STREAM_WINDOW_BYTES` per direction, `stream-window` tops it up additively,
  and `MAX_STREAM_DATA_CHUNK_BYTES` caps one frame's payload. Loosening either bound
  re-introduces head-of-line blocking between bulk and control traffic.
- **`git-receive-pack` stays structurally absent.** Validation, matching, and profile
  checks each refuse it. Do not weaken one layer because another still holds.
- **Connector webhook schemes are version-bound.** `secret-token` is the explicit
  GitLab 18.11 scheme and `signing-token` is the GitLab 19+ scheme. The listener never
  infers from header presence or falls back, and the hub binds the frame to the stored scheme.
- **Closed unions (`StreamErrorCode`, `ConnectionErrorCode`, `WebhookVerificationScheme`,
  `StreamCloseReason`, `FRAME_TYPES`)** are guarded by the sample-coverage test in
  `frames.test.ts`: adding a member without a round-trip sample fails the suite.
- Tests compile with `tsc` and run on `dist/` via `node --test`
  (`pnpm --filter @heedvane/connector-protocol test`), the same pattern as `apps/api`.
