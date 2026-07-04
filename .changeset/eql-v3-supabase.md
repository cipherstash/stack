---
'@cipherstash/stack': minor
'stash': minor
---

Add EQL v3 Supabase support.

`@cipherstash/stack/supabase` gains `encryptedSupabaseV3` — the EQL v3
counterpart of `encryptedSupabase` for schemas authored with
`@cipherstash/stack/eql/v3`. The public surface and call shape are identical
to v2 (same filter methods, `withLockContext`, `audit`); only the schema type
and wire encoding differ:

- columns are stored in their native `eql_v3.*` domains (raw jsonb payloads,
  no composite wrap), with JS property → DB column name resolution and `Date`
  reconstruction from `cast_as` on decrypted rows;
- filter operands are full storage envelopes (every `eql_v3.*` domain CHECK
  requires the storage keys, and the SQL operators coerce their operand into
  the domain);
- `like`/`ilike` on encrypted columns are emitted as PostgREST `cs`
  (bloom-filter `@>`) — the v3 domains define no LIKE operator;
- filters on storage-only columns (e.g. `types.Bool`) and null filter values
  are rejected at the type level and at runtime.

The v3 builder's default row type is exactly the table's inferred plaintext
shape (no index-signature widening — widening would disable the storage-only
filter guard). Filtering or inserting plaintext passthrough columns requires
an explicit row type: `es.from<typeof users, UserRow>('users', users)`.

The CLI gains an EQL v3 path: `stash db install --eql-version 3` installs the
vendored v3 bundle (`--supabase` selects the opclass-stripped variant and
applies the `eql_v3` grants for the Supabase roles); `stash db upgrade` also
accepts `--eql-version`, and `stash db status` reports v2 and v3 installs
independently. The v2 `SUPABASE_PERMISSIONS_SQL` block is now generated from a
shared `supabasePermissionsSql(schemaName)` helper, with
`SUPABASE_PERMISSIONS_SQL_V3` keyed to `eql_v3`.
