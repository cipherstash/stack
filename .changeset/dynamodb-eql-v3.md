---
'@cipherstash/stack': minor
'stash': patch
---

`encryptedDynamoDB` now accepts EQL v3 tables.

Pass a table built with `encryptedTable` + the `types.*` domains from
`@cipherstash/stack/v3` (or `@cipherstash/stack/eql/v3`) to any of
`encryptModel`, `bulkEncryptModels`, `decryptModel`, `bulkDecryptModels`. Both
the typed client from `EncryptionV3` and the nominal client from
`Encryption({ config: { eqlVersion: 3 } })` are accepted.

EQL v2 tables continue to work unchanged — this is additive, and no existing
caller needs to change. The table decides which wire format is used, so a
DynamoDB table populated under one version must keep being read with that
version.

This fixes a latent bug that made v3 unusable: the write path detected an
encrypted value by its `k: 'ct'` tag, but EQL v3 scalars carry no `k`
discriminator at all. Every v3 scalar fell through to the nested-object branch
and was written as a raw map instead of being split into `<attr>__source` and
`<attr>__hmac`.

Notes on capability:

- Only equality is usable on DynamoDB. `<attr>__hmac` is written for domains
  that mint an `hm` term — the `*Eq` family, plus `TextOrd`/`TextOrdOre`/
  `TextSearch`. Ordering and bloom-filter terms have no DynamoDB query surface
  and are not stored, so those columns remain decryptable but not queryable.
- Nested attributes are supported in v3. There is no nested-group authoring
  form (that is a compile error), so declare the column flat with a dotted
  path — `{ 'profile.ssn': types.TextEq('profile.ssn') }`. The model is
  matched by dotted path, so `{ profile: { ssn } }` resolves, and the nested
  attribute keeps its `__hmac` for key conditions.
- Audit metadata on `decryptModel` / `bulkDecryptModels` requires the nominal
  client; the `EncryptionV3` client has no audit surface on decrypt.

The DynamoDB adapter also gains its first test coverage — 74 tests across the
v2 and v3 paths, where it previously had none.
