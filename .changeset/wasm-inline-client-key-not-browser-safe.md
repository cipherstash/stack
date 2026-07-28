---
'@cipherstash/stack': patch
'stash': patch
---

Document that `@cipherstash/stack/wasm-inline` is server-side only, and pin the
reason against the core.

`WasmClientConfig` requires `clientId` and `clientKey` on every auth arm,
including the `authStrategy` (OIDC federation) arm. That read like an
over-declaration the SDK could relax — if federation alone sufficed, a browser
could hold a client without a workspace secret. It cannot. The core requires
both fields regardless of strategy, and consumes `clientKey` as encryption key
material *before* the auth strategy is consulted. Since `clientKey` is a
workspace secret, no configuration of this entry belongs in a browser bundle —
which is why there is no `browser` export condition.

No behaviour change. The types and runtime are unchanged; what changes is that
the constraint is now stated where callers meet it (`WasmClientConfig`, the
auth-strategy re-export, and the entry-point table in `skills/stash-encryption`)
and enforced by a contract test that runs against the real WASM core instead of
the stub every other wasm suite uses.
