---
'@cipherstash/stack-drizzle': minor
'stash': patch
---

Type `extractEncryptionSchema` precisely: a Drizzle-extracted schema now preserves each column's concrete EQL v3 domain instead of widening to `AnyV3Table` (#589).

`extractEncryptionSchema` is generic over the Drizzle table (`<T extends PgTable>(table: T)`) and returns `EncryptedTable<Cols> & Cols`, the same shape a hand-written `encryptedTable({...})` returns. Each column's builder is carried through `pgTable()` on a phantom brand and recovered by a mapped type, which also filters out the table's non-encrypted columns.

What this fixes, along the documented flow `extractEncryptionSchema(table)` → `Encryption({ schemas })` → `bulkEncryptModels`:

- `InferPlaintext<typeof schema>` is a precise per-column plaintext map (`{ email: string; age: number }`) rather than an index signature.
- `encryptModel` / `bulkEncryptModels` check each schema field against its own domain's plaintext — a `string` written to an `IntegerOrd` column is now a compile error instead of an encrypt-time failure — and pass plain helper columns (`id`, a plain `text()`) through with their own types rather than typing them as encrypted.
- `schema.email` addresses the column at its concrete type, so `encrypt` / `encryptQuery` pin the value to that column's plaintext.

**Runtime behaviour is unchanged** — the runtime already recovered each column's builder correctly, so this is a type-level fix only. It is `minor` rather than `patch` because code that previously compiled against the widened types can now fail to compile: a model field typed against the wrong domain, or a schema-derived type that relied on the old index signature. Rows whose shape is only known at runtime (a dynamically built table) should name their model type explicitly — `client.bulkEncryptModels<typeof schema, MyRow>(rows, schema)` — rather than being cast back to `AnyV3Table`.

`skills/stash-drizzle` documents the preserved typing and warns against casting an extracted schema to `AnyV3Table` to make an insert compile.
