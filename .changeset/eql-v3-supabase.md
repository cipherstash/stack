---
'@cipherstash/stack': minor
'stash': minor
---

Add EQL v3 Supabase support, baselined on the `eql-3.0.0-alpha.2` release.

`@cipherstash/stack/supabase` gains `encryptedSupabaseV3` — the EQL v3
counterpart of `encryptedSupabase` for schemas authored with
`@cipherstash/stack/eql/v3`. The public surface and call shape are identical
to v2 (same filter methods, `withLockContext`, `audit`); only the schema type
and wire encoding differ.

**The v3 surface** is the `eql-3.0.0-alpha.2` release artifact: domains use
SQL-standard type names (`eql_v3.integer_ord`, `eql_v3.timestamp_ord`,
`eql_v3.boolean`, … mirrored by `types.IntegerOrd`, `types.TimestampOrd`,
`types.Boolean`, …), SEM internals live in a separate `eql_v3_internal`
schema (grant it roles, never expose it — only `eql_v3` goes in Supabase's
Exposed schemas), and envelopes are versioned `v: 3`. Envelope production
rides on `@cipherstash/protect-ffi` 0.27, which takes an `eqlVersion` so the
same client emits v2 or v3 payloads per schema.

**Adapter behaviour:**

- columns are stored in their native `eql_v3.*` domains (raw jsonb payloads,
  no composite wrap), with JS property → DB column name resolution and `Date`
  reconstruction from `cast_as` on decrypted rows;
- **INTERIM:** filter operands are full storage envelopes — every `eql_v3.*`
  domain CHECK requires the storage keys, and the SQL operators coerce their
  operand into the domain, so a term-only operand is rejected today. This is
  a tracked workaround (Linear CIP-3402), not the design: a full-envelope
  operand carries a real decryptable ciphertext plus all of the column's
  index terms, and PostgREST filters travel in GET query strings, so operands
  can land in URL logs, proxies, and Supabase request logs (query terms are
  index-terms-only by design). The fix is an EQL-side term-only scalar query
  envelope (the scalar analog of `eql_v3.jsonb_query`);
- `like`/`ilike` on encrypted columns are emitted as PostgREST `cs`
  (bloom-filter `@>`) — the v3 domains define no LIKE operator. Substring
  search currently also requires `include_original: false` on the match
  index; that requirement is a symptom of the same interim full-envelope
  operand and goes away with CIP-3402;
- filters on storage-only columns (e.g. `types.Boolean`) and null filter
  values are rejected at the type level and at runtime.

The v3 builder's default row type is exactly the table's inferred plaintext
shape (no index-signature widening — widening would disable the storage-only
filter guard). Filtering or inserting plaintext passthrough columns requires
an explicit row type: `es.from<typeof users, UserRow>('users', users)`.

The CLI gains an EQL v3 path: `stash eql install --eql-version 3` installs the
vendored `eql-3.0.0-alpha.2` bundle (`--supabase` selects the opclass-stripped
variant and applies the role grants for both `eql_v3` and `eql_v3_internal`);
`stash db upgrade` also accepts `--eql-version`, and `stash db status` reports
v2 and v3 installs independently. The v2 `SUPABASE_PERMISSIONS_SQL` block is
now generated from a shared `supabasePermissionsSql(schemaName)` helper, with
`SUPABASE_PERMISSIONS_SQL_V3` covering the v3 schemas.
