---
'@cipherstash/stack': patch
---

Fixed: `encryptQuery` on the typed EQL v3 client did not typecheck against the
published package — for any column.

```ts
const users = encryptedTable('users', { email: types.TextSearch('email') })
const client = await Encryption({ schemas: [users] })

client.encrypt('a@b.com', { table: users, column: users.email })      // fine
client.encryptQuery('a@b.com', { table: users, column: users.email })
// TS2345: Argument of type '"a@b.com"' is not assignable to parameter of type 'never'
```

`PlaintextForColumn` and `QueryTypesForColumn` recover a column's domain with
`C extends EncryptedV3Column<infer D>`, which needs `D` to appear bare somewhere
in the instance type. Its only bare occurrence was a **private** field, and
`tsc` strips the types of private members on declaration emit — so in the
shipped `.d.ts` the inference fell back to the `V3DomainDefinition` constraint.
`QueryTypesForColumn` collapsed to `never`, which made `QueryableColumnsOf`
`never`, which typed every query plaintext `never`. `encrypt` was unaffected
because it resolves through `ColumnsOf`.

`EncryptedV3Column` now carries a type-only `declare readonly __domain?: D`.
Nothing is emitted at runtime and no call site changes; the declaration survives
emit and restores the inference site.

This affected every published release with the v3 typed client, including
`1.0.0-rc.4` — the searchable-query recipes in the `stash-encryption` skill did
not compile in a customer's repo. It was invisible in CI because the type tests
import source rather than `dist/`; a new `test:types:dist` suite now typechecks
the emitted declarations and is wired into CI.
