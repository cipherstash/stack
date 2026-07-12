# @cipherstash/prisma-next

**Searchable field-level encryption for Postgres with [Prisma Next](https://www.npmjs.com/package/prisma-next)** — powered by [`@cipherstash/stack`](../stack/README.md) and the [EQL bundle](https://cipherstash.com/docs/stack/platform/eql).

Declare encrypted columns directly in `schema.prisma`, and the framework's migration system installs the EQL bundle in the same control-plane sweep that creates your tables. No separate "install EQL" step.

📖 **[Full documentation →](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next)**

## Features

- 🔒 Six encrypted column types — `string`, `double`, `bigint`, `date`, `boolean`, `json`
- 🔍 Searchable encryption — equality, free-text search, range, order, JSON path and containment
- 🎯 17 type-safe query operators (`cipherstashEq`, `cipherstashIlike`, `cipherstashGt`, `cipherstashAsc`, …)
- ⚡ Bulk encrypt / bulk decrypt coalescing — one SDK round-trip per `(table, column)` group per query
- 🧩 One-call setup via `cipherstashFromStack({ contractJson })` — no duplicate stack schema to maintain
- 🛡️ Plaintext redaction on every implicit serialisation path (`toJSON`, `toString`, `util.inspect`, …)

## Installation

```bash
npm install @cipherstash/stack @cipherstash/prisma-next
```

## Quick start

```prisma
// prisma/schema.prisma
model User {
  id            String @id
  email         cipherstash.EncryptedString()
  salary        cipherstash.EncryptedDouble()
  birthday      cipherstash.EncryptedDate()
  preferences   cipherstash.EncryptedJson()
}
```

```typescript
// prisma-next.config.ts
import cipherstash from "@cipherstash/prisma-next/control"
// ... other imports
export default defineConfig({
  // ... family, target, adapter, contract
  extensionPacks: [cipherstash],
})
```

```typescript
// src/db.ts
import "dotenv/config"
import { cipherstashFromStack } from "@cipherstash/prisma-next/stack"
import postgres from "@prisma-next/postgres/runtime"
import type { Contract } from "./prisma/contract.d"
import contractJson from "./prisma/contract.json" with { type: "json" }

const cipherstash = await cipherstashFromStack({ contractJson })

export const db = postgres<Contract>({
  contractJson,
  extensions: cipherstash.extensions,
  middleware: cipherstash.middleware,
})
```

```bash
npx stash auth login                      # one-time, per developer
npx prisma-next contract emit
npx prisma-next migration plan --name initial
npx prisma-next migration apply           # installs EQL bundle + your schema
```

```typescript
import { EncryptedString, decryptAll } from "@cipherstash/prisma-next/runtime"

await db.orm.public.User.create({
  id: "user-0",
  email: EncryptedString.from("alice@example.com"),
  // ...
})

const rows = await db.orm.public.User
  .where((u) => u.email.cipherstashIlike("%@example.com"))
  .all()

await decryptAll(rows)
console.log(await rows[0]?.email.decrypt())
```

See the [full documentation](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) for the complete encrypted column reference, all 17 query operators, the override surface, security model, and known limitations.

## Subpath exports

| Subpath          | Purpose                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `./stack`        | One-call setup against `@cipherstash/stack`: `cipherstashFromStack`, `deriveStackSchemas`, `createCipherstashSdk` |
| `./control`      | `SqlControlExtensionDescriptor` (contract space + pack meta + codec lifecycle hooks)                   |
| `./runtime`      | Six envelope classes + `CipherstashSdk` + codec runtime + `decryptAll` + four free-standing helpers    |
| `./middleware`   | `bulkEncryptMiddleware(sdk)`                                                                           |
| `./pack`         | `cipherstashPackMeta` for TS contract authoring                                                        |
| `./column-types` | Six TS factories: `encryptedString` / `encryptedDouble` / `encryptedBigInt` / `encryptedDate` / `encryptedBoolean` / `encryptedJson` |

`./control`, `./runtime`, and `./middleware` are tree-shakable. `./stack` sits on top of `./runtime` + `./middleware` and additionally pulls in `@cipherstash/stack`; consumers who implement `CipherstashSdk` against a different KMS skip `./stack` and pay no `@cipherstash/stack` bundle cost.

## Authentication

There are 2 main ways to authenticate to CipherStash:

### Local profile (Dev)

`npx stash auth login` lets you log in via the browser and saves credentials in the CipherStash profile (`~/.cipherstash`). A key is automatically generated and granted access to the default keyset.

### Env vars (Production)

The four `CS_*` env vars (`CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`) are reserved for production deployments and CI runners. See the [authentication docs](https://cipherstash.com/docs/stack/encryption/prisma-next#authentication) for more information.

## Example

A runnable end-to-end example lives at [`examples/prisma/`](../../examples/prisma/) — bundles a docker-compose Postgres, a six-codec `User` schema, and a flow that exercises every operator category against a live ZeroKMS workspace.

## Contributing

See [`DEVELOPING.md`](./DEVELOPING.md) for the source layout, two-pass codec encode + middleware rewrite lifecycle, physical-column-name routing, the `bigint → Number` SDK boundary, and other runtime-side details.

## References

- 📖 [**Full docs**](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) — column types, operator reference, security model, known limitations.
- [CipherStash EQL reference](https://cipherstash.com/docs/stack/platform/eql) — encrypted operator semantics and search-config index types.
- [`@cipherstash/stack`](../stack/README.md) — encryption SDK and schema DSL.
- [Prisma Next](https://www.npmjs.com/package/prisma-next) — the framework this extension plugs into.

## License

MIT
