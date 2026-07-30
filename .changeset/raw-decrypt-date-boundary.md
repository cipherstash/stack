---
'@cipherstash/stack': patch
'stash': patch
---

Document the `Date` reconstruction boundary on `decrypt` / `bulkDecrypt`, and correct the reason given for it.

A `types.Date` / `types.Timestamp` column comes back as a `Date` from `decryptModel(row, table)` and as the string it was stored as from `decrypt(payload)` / `bulkDecrypt(payloads)`. Reconstruction is driven by the table's `cast_as`, and only the model path is handed a table. That split is intentional — the raw methods resolve to the FFI plaintext union, which excludes `Date`, so reconstructing without widening the return type would make the declared type wrong — but it was undocumented, and the JSDoc explained it with a reason that does not hold: that a lone ciphertext "carries no column identity". Every stored payload carries `i: { t, c }`, so the identity is present and simply unused. The real constraint is static typing (TypeScript cannot know which column a runtime payload came from), not a missing capability at runtime.

No behaviour change. What changed:

- `decrypt` and the new `bulkDecrypt` JSDoc state the boundary, its consequence, and the actual reason, on both the native and `wasm-inline` entries.
- The one-arg `decryptModel(row)` / `bulkDecryptModels(rows)` overloads had the same wrong justification ("there is no `cast_as` to reconstruct from"); corrected to name the real one — the `table` argument is what selects reconstruction, and `Decrypted<T>` types those fields `string` to match.
- `skills/stash-encryption` and the `@cipherstash/stack` README now call out the `Date`-vs-string consequence and point at the model helpers. Both also stop calling `bulkEncrypt` untyped: its plaintexts are pinned to the column's domain via `{ table, column }`, exactly like `encrypt` — it is `bulkDecrypt`, which takes the payloads alone, that resolves to the untyped plaintext union.
- `bulkDecrypt` was the one path with no test either way; it is now pinned, using a payload whose `i: { t, c }` names a registered date-like column, so a future change of heart is a deliberate decision rather than a silent drift.
- The boundary is pinned at the type layer too, which is the layer it is argued from: the raw paths resolve to the FFI plaintext union with no `Date` arm, the table-taking model path resolves to `Date`, and the table-less one to `string`. If `JsPlaintext` ever gains a `Date` arm upstream, the justification for the split expires — and the type tests fail rather than the docs quietly going stale.

Resolves #779.
