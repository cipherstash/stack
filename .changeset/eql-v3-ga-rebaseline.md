---
'@cipherstash/stack': minor
---

Re-baseline EQL v3 on the eql-3.0.0 GA release and protect-ffi 0.29.

- **Breaking (v3 preview surface):** the EQL v3 column domains follow the
  eql-3.0.0 naming convention — flat, prefixed names in `public`
  (`public.eql_v3_text_search`, `public.eql_v3_integer_ord`, …) instead of the
  alpha-era bare names. Databases installed from an alpha bundle must be
  re-installed (`stash eql install` replaces the schema).
- `encryptQuery` on the EQL v3 client now returns EQL v3 query operands
  (protect-ffi 0.29): term-only scalar operands for the `eql_v3.query_<name>`
  domains, the `eql_v3.query_jsonb` containment needle, and bare selector
  hashes for JSON path queries — v3 scalar and selector queries no longer
  throw `EQL_V3_QUERY_UNSUPPORTED` (the code is gone).
- Legacy EQL v2 JSON compatibility fixtures pin the SteVec encoding to
  `standard` explicitly. protect-ffi 0.29 flipped the library default to
  `compat` (EQL v3's encoding); without the pin, v2 JSON containment fixtures
  would silently mismatch existing data.
- The EQL v3 test/install SQL is sourced from the pinned `@cipherstash/eql`
  package (3.0.0) instead of a hand-vendored fixture.
