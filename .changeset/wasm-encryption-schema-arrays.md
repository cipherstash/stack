---
'@cipherstash/stack': patch
---

The `@cipherstash/stack/wasm-inline` `Encryption` factory now accepts the same
schema-array shapes the native entry does.

`WasmEncryptionConfig.schemas` was a mutable non-empty tuple
(`[AnyV3Table, ...AnyV3Table[]]`), which rejects every form that is not an array
literal: a shared `export const all: AnyV3Table[]`, a `ReadonlyArray`, a
`.map()` result, anything spread or push-built. The native factory was widened
to `readonly AnyV3Table[]` for exactly that reason; the WASM twin kept the
tuple, so the two entries disagreed about identical calls while their runtimes
agreed exactly (both check only `schemas.length`).

Non-emptiness moves to the `Encryption` overloads, so `Encryption({ schemas: [] })`
remains a compile error on this entry too. The built `wasm-inline.d.ts` is now
covered by the declaration gate, which is where this drift went unnoticed — the
entry gets its own tsup DTS pass that no source-level type test can see.
