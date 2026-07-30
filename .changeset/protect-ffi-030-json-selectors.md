---
'@cipherstash/stack': minor
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack-supabase': patch
'@cipherstash/stack-prisma': minor
'stash': patch
---

Upgrade Stack to `@cipherstash/protect-ffi` 0.30 and EQL 3.0.2.

Prisma Next includes a versioned EQL 3.0.2 upgrade migration, so databases
that have already recorded the original EQL v3 baseline still install the new
domains and functions.

Encrypted JSON now uses the `public.eql_v3_json_search` storage domain and
`eql_v3.query_json` query domain. Drizzle selector equality uses exact,
GIN-indexable value-selector containment, while selector range comparisons use
a ciphertext-free path selector plus string/number query term. Prisma Next gains
the equivalent `eqlJsonPathEq`, `eqlJsonPathNeq`, `eqlJsonPathGt`,
`eqlJsonPathGte`, `eqlJsonPathLt`, and `eqlJsonPathLte` operators. Selector
Selector-based `ORDER BY` is available as
`ops.selector(column, path).asc()/desc()` in Drizzle
and `eqlJsonPathAsc(column, path)` / `eqlJsonPathDesc(column, path)` in Prisma
Next; both lower to `ORDER BY eql_v3.ord_term` over the selected entry.

If you call `encryptQuery` with an explicit `queryType`, note that `steVecTerm`
now produces a scalar JSON ordering term. It no longer means structural
containment; use the JSON containment query type with an object or array, or
`steVecValueSelector` with
`{ path, value }` for exact equality at a path.

The FFI now rejects free-text needles shorter than the configured n-gram size
at the core query-encryption boundary, including callers that bypass adapter
guards.

This EQL release changes the SteVec storage format. Existing EQL v3 encrypted
JSON rows must be re-encrypted before they can be queried with the new domain.
The former EQL v2 JSON schema shape is not accepted by the public client because
the old selector envelope can no longer be emitted; migrate to the v3
`types.Json` domain. Native decrypt compatibility for stored v2 payloads is
unchanged.

EQL 3.0.2 requires typed query-domain operands for encrypted free-text and JSON
operators. PostgREST cannot express those casts, so Supabase v3 fails fast for
`matches()`, encrypted `contains()`, and `selectorEq()`/`selectorNe()` instead
of placing a decryptable storage envelope in a GET query string that the new
SQL surface will reject. Use the Drizzle or Prisma Next adapter, or a carefully
scoped direct SQL/RPC path.
