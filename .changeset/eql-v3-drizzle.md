---
'@cipherstash/stack-drizzle': minor
---

EQL v3 Drizzle support on the `@cipherstash/stack-drizzle` package root. A
Drizzle-native `types` namespace (same PascalCase names as
`@cipherstash/stack/eql/v3`) declares encrypted columns whose Postgres type is
the semantic `public.eql_v3_<domain>`; the concrete type drives the legal query
operators. `createEncryptionOperators` provides capability-checked
`eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`matches`/`contains`/`inArray`/
`asc`/`desc`/`and`/`or` that emit the two-argument `eql_v3` SQL functions with
full-envelope operands, and `extractEncryptionSchema` rebuilds the schema for
`Encryption`.

The encrypted free-text helper is `matches`; obsolete `like`/`ilike` helpers are
not exposed, because encrypted free-text search is bloom-filter token matching
rather than SQL wildcard matching. `contains` is genuine encrypted-JSON
containment (`@>` against a `types.Json` column), not free-text.
