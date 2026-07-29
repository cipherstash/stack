---
'@cipherstash/stack': minor
'@cipherstash/prisma-next': patch
---

`Encryption({ schemas })` now accepts any non-empty array of EQL v3 tables, not
only an array literal.

Previously the v3 signature required a non-empty *tuple*, so every indirect form
was rejected at compile time even though it worked at runtime:

```ts
// all of these used to fail with TS2769
export const schemas: AnyV3Table[] = [users, orders]
await Encryption({ schemas })

const readonlySchemas: ReadonlyArray<AnyV3Table> = [users, orders]
await Encryption({ schemas: readonlySchemas })

const built: AnyV3Table[] = []
built.push(users)
await Encryption({ schemas: built })
```

They all compile now. `Encryption({ schemas: [] })` is still a compile error, and
an array literal still gets full per-column typing — passing the wrong plaintext
for a column's domain, or a table the client was not built with, is still
rejected.

`EncryptionClient<S>` accepts the same schema parameter, so it names the client
for a loose `readonly AnyV3Table[]` as well as for a tuple. Code that is generic
over its schemas — an adapter that builds a table per request, say — can write
`EncryptionClient<readonly AnyV3Table[]>`.

That keeps the `table` and `column` arguments checked, but not the model input:
with the schema parameter loose there is no per-column plaintext to resolve, so
`encryptModel` / `bulkEncryptModels` still reject an untyped
`Record<string, unknown>` model and an adapter holding untyped rows needs a cast
at that one boundary. Full model typing requires a concrete schema tuple.

If you narrowed a schema array to `readonly [AnyV3Table, ...AnyV3Table[]]` to
satisfy the old signature, that narrowing is no longer needed.

A wrapper that is itself generic over its schemas keeps working too:

```ts
async function makeClient<S extends readonly [AnyV3Table, ...AnyV3Table[]]>(
  schemas: S,
) {
  return await Encryption({ schemas })
}
```

Note the non-empty tuple constraint. A wrapper generic over a loose
`readonly AnyV3Table[]` is still rejected — that type admits `readonly []`, so
the wrapper cannot promise what `Encryption` requires. Constrain it as above, or
take `EncryptionClient<readonly AnyV3Table[]>` as a parameter instead of
building the client inside the generic function.
