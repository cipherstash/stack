---
'@cipherstash/stack': major
'@cipherstash/stack-drizzle': major
'@cipherstash/stack-supabase': major
---

CipherStash Stack 1.0 — EQL v3 general availability.

The first stable (1.0) release of `@cipherstash/stack` and its adapter packages,
built on EQL v3 (`eql-3.0.0`) and `@cipherstash/protect-ffi` 0.29:

- Typed v3 schema authoring (`types` / `encryptedTable` from
  `@cipherstash/stack/eql/v3`) and a typed encryption client (`EncryptionV3`
  from `@cipherstash/stack/v3`).
- EQL v3 Drizzle and Supabase integrations, split into their own packages —
  `@cipherstash/stack-drizzle` and `@cipherstash/stack-supabase`.

This is a breaking, major release. See the individual package CHANGELOGs for the
full v3 surface. The previous EQL v2 (0.x) line remains available under its
published release tags (`@cipherstash/stack@0.x`).
