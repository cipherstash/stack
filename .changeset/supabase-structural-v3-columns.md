---
'@cipherstash/stack-supabase': patch
---

Fix: a table authored with `encryptedTable`/`types` imported from `@cipherstash/stack/wasm-inline` was treated as having **no encrypted columns**, so filter operands were sent to PostgREST as plaintext.

`ColumnMap` gated on `builder instanceof EncryptedV3Column`, and the published bundles contain two separately-emitted copies of that class (`dist/adapter-kit.js` and `dist/wasm-inline.js` are separate esbuild runs). The check is now structural, so both copies are recognised. Tables authored from `@cipherstash/stack/eql/v3` were never affected — they resolve to the same copy the adapter imports.

The failure was silent: `::jsonb` casts and result decryption go through a different path and kept working.

The recognition now also fails closed: a column builder that does not present the v3 surface makes `encryptedSupabase` throw at construction rather than silently omitting the column — an omitted column would send its filter operands to PostgREST as plaintext.
