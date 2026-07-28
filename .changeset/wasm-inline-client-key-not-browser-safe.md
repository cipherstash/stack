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
both fields regardless of strategy, and loads `clientKey` as encryption key
material *before* it ever calls the auth strategy. Since `clientKey` is a
workspace secret, no configuration of this entry belongs in a browser bundle —
which is why this entry has no `browser` export condition, and will not get one
until the core changes.

No behaviour change. The types and runtime are unchanged; what changes is that
the constraint is now stated where callers meet it (`WasmClientConfig`, the
auth-strategy re-export, the `stash-encryption` entry-point table, the
`stash-edge` and `stash-supabase` skills, and the `supabase-worker` example,
which had all described this entry as browser-capable) and enforced by contract
tests that run against the real WASM core instead of the mocks and stub the rest
of the wasm suite uses.
