---
'@cipherstash/stack-supabase': major
---

Remove the EQL v2 authoring surface and de-suffix the v3 API to the canonical
unsuffixed names (part of the EQL v2 removal, #707).

- **`encryptedSupabase` is now the connect-time-introspecting EQL v3 factory**
  (formerly `encryptedSupabaseV3`). `encryptedSupabaseV3` remains as a
  type-identical `@deprecated` alias, so existing imports keep working.
- **The legacy v2 `encryptedSupabase({ encryptionClient, supabaseClient })`
  wrapper is removed** — with it the two-argument `from(tableName, schema)` form
  and the hand-written client-side v2 schema. Its `EncryptedSupabaseConfig` and
  the v2 `EncryptedSupabaseInstance`/`EncryptedQueryBuilder` type shapes are gone;
  the unsuffixed type names now denote the v3 surface.
- **The `*V3` type exports are de-suffixed** to their canonical names —
  `EncryptedSupabaseV3Options` → `EncryptedSupabaseOptions`,
  `EncryptedSupabaseV3Instance` → `EncryptedSupabaseInstance`,
  `TypedEncryptedSupabaseV3Instance` → `TypedEncryptedSupabaseInstance`,
  `EncryptedQueryBuilderV3` → `EncryptedQueryBuilder`,
  `EncryptedQueryBuilderV3Untyped` → `EncryptedQueryBuilderUntyped`,
  `V3FilterableKeys` → `FilterableKeys`, `V3OrderableKeys` → `OrderableKeys`, and
  the rest of the `*V3` key-helper types. Each keeps a type-identical
  `@deprecated` `*V3` alias.

**Not affected: reading existing data.** Only the v2 *authoring/emission* surface
is removed. Decryption in `@cipherstash/stack` is generation-agnostic, so rows
written as EQL v2 payloads still decrypt through the wrapper's read path.

Internally the v3 query builder (`query-builder-v3.ts`) was folded into the base
`EncryptedQueryBuilderImpl`, which is now natively EQL v3; no runtime behaviour or
wire encoding changed.

**Migration:** rename `encryptedSupabaseV3` → `encryptedSupabase` (or keep using
the alias). If you still use the v2 `encryptedSupabase({ encryptionClient,
supabaseClient }).from(table, schema)` wrapper, migrate the table to an
`eql_v3_*` column domain and switch to the introspecting factory —
`await encryptedSupabase(supabaseUrl, supabaseKey)` — see the `stash-supabase`
skill and https://cipherstash.com/docs.
