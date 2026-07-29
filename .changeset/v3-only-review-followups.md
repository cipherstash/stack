---
'@cipherstash/stack': patch
---

Three fixes to the EQL v3-only surface.

**DynamoDB: grouped v2 `date` / `timestamp` columns now reconstruct to `Date`.**
A legacy grouped field is stored as `<group>.<leaf>__source` while the v2 schema
knew it only as `<leaf>`, so a `{ storedEqlVersion: 2 }` read matches it by its
bare leaf and writes the plaintext back at the nested path (`details.placedAt`).
Both clients resolve their date columns from the *declared* paths, so neither
reconstructed that value and it came back as an ISO string. The read path now
reports the path it actually wrote to and the adapter reconstructs there —
covering the native and `wasm-inline` entries, on `decryptModel` and
`bulkDecryptModels` alike. Carrying a grouped date forward as a plain top-level
column no longer requires re-declaring it as a dotted path.

**`EncryptionClientConfig` no longer accepts an empty schema set.** Its default
type argument widened to `readonly AnyV3Table[]`, where `S['length']` resolves to
`number` and the non-empty conditional stopped firing, so
`const cfg: EncryptionClientConfig = { schemas: [] }` typechecked and then threw
at `Encryption(cfg)`. The default is a non-empty tuple again, matching
`WasmEncryptionConfig`. The factory still accepts widened arrays passed inline.

**`config.eqlVersion: undefined` is tolerated at runtime.** `eqlVersion?: never`
admits an explicit `undefined` (this repo does not enable
`exactOptionalPropertyTypes`, and no declaration can reject it), but both
factories threw on the mere presence of the key — failing a config the published
types accept. An explicit `undefined` names no version and is now allowed; every
real value, `eqlVersion: 3` included, is still rejected.
