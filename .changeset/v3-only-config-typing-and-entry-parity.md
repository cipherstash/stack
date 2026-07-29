---
'@cipherstash/stack': major
'@cipherstash/prisma-next': patch
'stash': patch
---

Close the gaps found reviewing the v3-only change against #815's acceptance
criteria.

`config.eqlVersion` is now rejected by the type system as well as at runtime, on
both entries. `ClientConfig.eqlVersion` and `WasmClientConfig.eqlVersion` are
declared `?: never` rather than omitted: every other property on those types is
optional, so excess-property checking was the only thing catching a leftover
`eqlVersion` — and that fires on fresh object literals alone. A shared config
const, which is the shape a v2 → v3 migration actually holds, type-checked clean
and then threw at `Encryption()`. It is now a compile error. Both entries keep
their runtime guard, since JS and JSON callers bypass types entirely.

`@cipherstash/stack/wasm-inline` now rejects `config.eqlVersion` at runtime too,
with the same message as the native entry. Previously the native factory threw
and the WASM one accepted the field silently — the entry disagreement #815 exists
to remove.

The WASM entry's non-v3-table error no longer refers the reader to the native
entry for EQL v2 authoring. Authoring v2 has been removed everywhere, so that
referral only bought a second rejection; the message now says so and points at
what v2 payloads are still good for — decryption, which is unchanged.

The `Encryption` signature sketch in the `@cipherstash/stack` README carried
`schemas: AnyV3Table[]`, understating what is accepted; it now shows both real
overloads, including the `readonly` and non-literal array forms. The bundled
`stash-encryption` skill regained the `./encryption` and `./adapter-kit` subpath
rows, both of which still ship. `cipherstashFromStack`'s `encryptionConfig`
JSDoc described `config.eqlVersion` as an escape hatch that throws over an
all-v3 schema set; it is rejected unconditionally, and the doc now says that.

The `stash-dynamodb` skill documented the v3 descriptor a legacy read takes but
not that it must also be one of the tables passed to `Encryption({ schemas })`.
The adapter forwards that descriptor to the client, which rejects a table it was
not initialized with, so reading v2 rows for a table your current schema no
longer declares fails. That requirement is now stated where the legacy-read
signature is.
