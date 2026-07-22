---
'@cipherstash/stack': minor
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

`EncryptionV3` is now a deprecated, type-identical alias of `Encryption`:
`Encryption` is overloaded so an array of concrete EQL v3 tables yields the same
strongly-typed client. Use `Encryption` for new code. As part of this collapse
`EncryptionV3` no longer independently pins the wire format — like `Encryption`,
it now honours an explicit `config.eqlVersion` (the retained migration escape
hatch). The `eqlVersion` config field and the `@cipherstash/stack/schema` EQL v2
builders remain available (now marked `@deprecated`) for reading and migrating
legacy v2 data; the client authors EQL v3 only. Their full removal is deferred to
a later PR.
