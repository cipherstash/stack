---
'@cipherstash/prisma-next': major
---

**Breaking:** `CipherstashFromStackV3Options.encryptionConfig` — the config
passed through to the encryption client by `cipherstashFromStack` — uses the
v3-only `ClientConfig`. The public version-selection field has been removed, so
forcing EQL v2 no longer type-checks:

```ts
const cipherstash = await cipherstashFromStack({
  contractJson,
  encryptionConfig: { /* credentials and auth options only */ },
})
```

The option never did what it looked like it did. This package is EQL v3 only,
and `cipherstashFromStack` always builds from an all-v3 schema set, over which
`eqlVersion: 2` is refused at setup — v2 payloads cannot satisfy the columns'
`eql_v3_*` domains. The field promised a client it could never return.

**Migration:** drop the `eqlVersion` field. Every other `ClientConfig` option
(`workspaceCrn`, `clientId`, `clientKey`, `accessKey`, `authStrategy`, logging,
…) is unchanged and still accepted.

To read legacy EQL v2 rows, use the returned native `encryptionClient` —
`decrypt(…)` for a single value, or the no-table `decryptModel(row)` /
`bulkDecryptModels(rows)` form for whole models. Native decrypt is
generation-agnostic even though all new writes are EQL v3.
