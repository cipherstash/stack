---
'@cipherstash/stack': major
---

The typed EQL v3 client's `decryptModel` / `bulkDecryptModels` are now
audit-chainable. They return a chainable operation (a `MappedDecryptOperation`)
instead of a bare `Promise<Result<…>>`, so you can attach audit metadata and a
lock context before awaiting:

```typescript
await client
  .decryptModel(item, table)
  .audit({ metadata: { requestId } })
  .withLockContext({ identityClaim: ["sub"] })
```

Both chaining orders forward the metadata to ZeroKMS, and the `Date`
reconstruction still applies to the successful result. Await-only call sites are
unchanged — the operation is still thenable to the same `Result`. This restores
audited decrypt through the DynamoDB adapter (`encryptedDynamoDB(...).decryptModel`)
for a v3 client, which previously had nowhere to carry the metadata.

Chaining `.withLockContext()` onto a decrypt operation that already took a lock
context positionally (`decryptModel(item, table, lc).withLockContext(other)`) now
throws instead of silently keeping the first. Pass the lock context one way or
the other, not both.

**Breaking:** `Encryption` now accepts concrete EQL v3 tables and returns the
single strongly typed `EncryptionClient<S>` surface. The former v3 factory and
client aliases have been removed. If you were already passing EQL v3 tables to
`Encryption`, model decrypt now reconstructs `Date` columns from `cast_as`
instead of leaving them as ISO strings. Code that read those columns as strings
needs updating.

`Encryption({ schemas: [] })` no longer type-checks (it used to compile and then
throw). The public config no longer selects an EQL wire version: new clients
always author EQL v3. Name a client for a schema set as `EncryptionClient<S>`.

`decryptModel` / `bulkDecryptModels` on the typed client also accept a call with
no table, matching the runtime, which has always allowed it — that is the path
for reading models written before the upgrade, above all legacy EQL v2 ones,
whose table cannot be a member of a v3 schema tuple. Prefer the two-argument
form whenever the table is registered.

The public EQL v2 schema builders and version-selection config have been removed.
Native decrypt operations remain able to read legacy EQL v2 payloads.
