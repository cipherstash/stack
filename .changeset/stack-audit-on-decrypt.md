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

**Breaking:** `EncryptionV3` is now a deprecated, type-identical alias of
`Encryption`: `Encryption` is overloaded so an array of concrete EQL v3 tables
yields the same strongly-typed client. Use `Encryption` for new code. If you were
already passing EQL v3 tables to plain `Encryption`, you now receive the typed
client rather than the nominal one — its `decryptModel` / `bulkDecryptModels`
return type changes, and the two-argument form reconstructs `Date` columns from
`cast_as` instead of leaving them as ISO strings. Code that read those columns as
strings needs updating.

The v3 overload takes a non-empty tuple of tables and a `V3ClientConfig` —
`ClientConfig` without the deprecated `eqlVersion` escape hatch. So
`Encryption({ schemas: [] })` no longer type-checks (it used to compile and then
throw), and `config: { eqlVersion: 2 }` selects the nominal overload, which is
the client you actually get back. Callers passing a plain `AnyV3Table[]` rather
than an array literal must narrow it to `readonly [AnyV3Table, ...AnyV3Table[]]`.
`Awaited<ReturnType<typeof Encryption>>` names the nominal client whatever you
pass, because `ReturnType` reads the last overload; use the exported
`EncryptionClientFor<S>` to name the client for a schema tuple.

`decryptModel` / `bulkDecryptModels` on the typed client also accept a call with
no table, matching the runtime, which has always allowed it — that is the path
for reading models written before the upgrade, above all legacy EQL v2 ones,
whose table cannot be a member of a v3 schema tuple. Prefer the two-argument
form whenever the table is registered.

The `eqlVersion` config field and the `@cipherstash/stack/schema` EQL v2
builders remain available (now marked `@deprecated`) for reading and migrating
legacy v2 data; the client authors EQL v3 only. Their full removal is deferred to
a later PR.
