---
'@cipherstash/prisma-next': major
---

**Breaking:** `CipherstashFromStackV3Options.encryptionConfig` — the config
passed through to the encryption client by `cipherstashFromStack` — is narrowed
from `ClientConfig` to `V3ClientConfig` (`ClientConfig` without the legacy
`eqlVersion: 2` escape hatch). Forcing EQL v2 no longer type-checks:

```ts
const cipherstash = await cipherstashFromStack({
  contractJson,
  encryptionConfig: { eqlVersion: 2 },
  //                  ^^^^^^^^^^ error TS2322: Type '2' is not assignable to type '3'.
})
```

The option never did what it looked like it did. This package is EQL v3 only,
and `cipherstashFromStack` always builds from an all-v3 schema set, over which
`eqlVersion: 2` is refused at setup — v2 payloads cannot satisfy the columns'
`eql_v3_*` domains. The field promised a client it could never return.

**Migration:** drop the `eqlVersion` field. Every other `ClientConfig` option
(`workspaceCrn`, `clientId`, `clientKey`, `accessKey`, `authStrategy`, logging,
…) is unchanged and still accepted.

To read legacy EQL v2 rows, decrypt through `@cipherstash/stack` rather than
asking this adapter for a v2 client: the decrypt path is generation-agnostic and
reads both v2 and v3 payloads. Use the returned `encryptionClient` — `decrypt(…)`
for a single value, or the no-table `decryptModel(row)` / `bulkDecryptModels(rows)`
form for whole models, which is the supported path for models written before the
v3 upgrade.
