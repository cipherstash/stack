---
'@cipherstash/eql': patch
---

Encrypted JSON arrays now agree between the Rust/TypeScript bindings and the SQL. `SteVecDocument` models the root `a` array flag that the SQL root validator accepts and the array accessors require, so an array document the database accepts also parses in the bindings. The `a` flag on documents and entries is now optional but not nullable in the generated TypeScript and JSON Schema (`a?: boolean`), matching the SQL CHECK; a `null` is rejected instead of failing later with a cast error. `eql_v3.jsonb_array_length` returns 0 for an empty array (it returned NULL), and `eql_v3.jsonb_array_elements` and `eql_v3.jsonb_document_contains(jsonb[], jsonb)` no longer raise "upper bound of FOR loop cannot be null" on one.
