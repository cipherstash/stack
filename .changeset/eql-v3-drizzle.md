---
"@cipherstash/stack": minor
---

Add EQL v3 Drizzle support at `@cipherstash/stack/eql/v3/drizzle`. A Drizzle-native
`types` namespace (same PascalCase names as `@cipherstash/stack/eql/v3`) declares
encrypted columns whose Postgres type is the semantic `public.<domain>`; the concrete
type drives the legal query operators. `createEncryptionOperatorsV3` provides
capability-checked `eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`between`/`contains`/`inArray`/
`asc`/`desc`/`and`/`or` that emit the latest two-argument `eql_v3` SQL functions with
full-envelope operands, and
`extractEncryptionSchemaV3` rebuilds the schema for `EncryptionV3`. The existing v2
`@cipherstash/stack/drizzle` integration is unchanged.

The v3 text-search helper is `contains`; obsolete `like`/`ilike` helpers are not
exposed because v3 free-text search is token containment rather than SQL wildcard
matching.
