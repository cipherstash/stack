---
'@cipherstash/prisma-next': minor
'stash': patch
---

Upgrade the Prisma Next integration to Prisma Next 0.16.

All `@prisma-next/*` dependencies move from `0.14.0` to `0.16.0`, in lockstep. The
CipherStash encryption surface is unchanged — column types, envelopes, the `eql*`
operators, `cipherstashFromStack`, and every subpath export behave exactly as before.

**Action required in your `prisma-next.config.ts`:** Prisma Next 0.15 stopped
materialising a placeholder namespace, so authoring a SQL contract now requires the
target's namespace factory. Add `createNamespace` to your `prismaContract(...)` call:

```typescript
import { postgresCreateNamespace } from '@prisma-next/target-postgres/types'

contract: prismaContract('./prisma/schema.prisma', {
  output: 'src/prisma/contract.json',
  target: postgresPack,
  createNamespace: postgresCreateNamespace,
}),
```

Without it, `prisma-next contract emit` fails at runtime with `createNamespace is
not a function`. The bundled `stash-prisma-next` skill documents this too.

The bundled EQL v3 baseline migration is re-emitted so its label and hash reflect
the pinned `@cipherstash/eql` 3.0.2 (the committed artifact still said 3.0.0).

Re-run `prisma-next contract emit` after upgrading. The regenerated
`contract.{json,d.ts}` picks up the 0.15/0.16 shape changes — the namespace
discriminator becomes the target-specific `'postgres-schema'` (was
`'sql-namespace'`), emit adds the `StorageColumnTypes` / `StorageColumnInputTypes`
maps and the `scalarList` capability marker, and foreign keys and their backing
indexes become discrete contract entities. Your contract's `storageHash` is
unaffected by the upgrade itself.
