---
'@cipherstash/stack': minor
---

Add `EncryptionClient.getSchemas()` — the tables passed to
`Encryption({ schemas })`, returned by reference.

This is the domain-bearing view of your schema. `getEncryptConfig()` returns
what the FFI consumes: each column builds to `{ cast_as, indexes }`, and the
concrete EQL v3 domain name is dropped. That makes `cast_as: 'number'` with an
`ope` index ambiguous across `eql_v3_integer_ord`, `smallint_ord`, `real_ord`,
`double_ord` and `numeric_ord` — so tooling that has to reason about the
*declared* domain (schema linting, drift-checking a live database's
`information_schema.columns.domain_name`) could not recover it from a client
alone.

`getSchemas()` closes that gap. Read a column's domain with
`column.getEqlType()`, its capabilities with `column.getQueryCapabilities()`,
and its DB name with `column.getName()`:

```typescript
for (const table of client.getSchemas()) {
  for (const column of Object.values(table.columnBuilders)) {
    console.log(table.tableName, column.getName(), column.getEqlType())
  }
}
```

`stash eql validate` is the first consumer.
