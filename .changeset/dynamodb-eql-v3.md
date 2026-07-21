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

The DynamoDB adapter also gains its first test coverage — across the v2 and v3
paths, where it previously had none.

Robustness, from review:

- Passing a v3 table to a client that never registered it (one built for a
  different schema set, so it is not in v3 mode for that table) now throws a
  clear, actionable error naming the table, instead of failing opaquely deep in
  the FFI.
- A malformed decrypt result from a non-conforming client is surfaced as a
  failure rather than resolving as a silent `undefined` success.
- Reading back a `<attr>__source` attribute that matches no declared column now
  logs a debug diagnostic instead of silently returning the raw ciphertext.
- Caller input that cannot be structurally cloned no longer reaches the FFI by
  reference — the "encryption never mutates a caller's object" guarantee holds
  on that path too.

The v3 overloads are strongly typed. `encryptModel` / `bulkEncryptModels` check
the input model against the table's column domains, and return the DynamoDB
attribute map that is actually written — the new exported `EncryptedAttributes`
type, where a declared column `email` becomes `email__source` (plus
`email__hmac` for the equality domains that mint one) rather than surviving as
`email`. `decryptModel` / `bulkDecryptModels` invert it via `DecryptedAttributes`.
`AnyEncryptedTable`, `DynamoDBEncryptionClient` and `AuditConfig` are now
exported from `@cipherstash/stack/dynamodb` so these signatures can be named.
The EQL v2 overloads are unchanged.
