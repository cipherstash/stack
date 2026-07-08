---
'@cipherstash/stack': minor
---

Add `encryptedSupabaseV3` — the EQL v3 dialect of the Supabase adapter, for
tables authored with `@cipherstash/stack/eql/v3` (native `public.*` concrete
domains, `eql_v3` operators). The v2 query mechanism (direct EQL operators over
PostgREST) is unchanged: `EncryptedQueryBuilderImpl` gains narrow protected
seams whose defaults preserve v2 byte-for-byte, and a v3 subclass overrides them
for property↔DB-name resolution (`buildColumnKeyMap`, aliased `prop:db::jsonb`
select casts), raw jsonb mutation payloads (no `eql_v2` composite wrap),
full-envelope filter operands (every `public.*` domain CHECK needs the storage
keys, so narrowed query terms are not usable), `like`/`ilike` → PostgREST `cs`
(bloom `@>`), `Date` reconstruction from `cast_as`, and capability validation
(filtering a storage-only column or with an unsupported query type throws a
typed + runtime error). Filter keys are type-narrowed to exclude storage-only
columns.
