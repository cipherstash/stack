<div align="center">
  <h1>@cipherstash/stack-prisma</h1>

  <p><b>Searchable field-level encryption for Postgres with <a href="https://www.npmjs.com/package/prisma-next">Prisma Next</a> — powered by <a href="https://www.npmjs.com/package/@cipherstash/stack">@cipherstash/stack</a> and the <a href="https://cipherstash.com/docs/stack/platform/eql?utm_source=github&utm_medium=stack_prisma_readme">EQL bundle</a>.</b></p>

  <a href="https://www.npmjs.com/package/@cipherstash/stack-prisma"><img alt="npm version" src="https://img.shields.io/npm/v/@cipherstash/stack-prisma.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://www.npmjs.com/package/@cipherstash/stack-prisma"><img alt="npm downloads" src="https://img.shields.io/npm/dm/@cipherstash/stack-prisma.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next?utm_source=github&utm_medium=stack_prisma_readme"><img alt="Docs" src="https://img.shields.io/badge/Docs-333333.svg?style=for-the-badge&logo=readthedocs&labelColor=333"></a>
  <a href="https://discord.gg/5qwXUFb6PB"><img alt="Discord" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Discord&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/@cipherstash/stack-prisma.svg?style=for-the-badge&labelColor=000000"></a>
</div>

Declare encrypted columns directly in `schema.prisma`, and the framework's migration system installs the EQL bundle in the same control-plane sweep that creates your tables. No separate "install EQL" step.

📖 **[Full documentation →](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next)**

## Features

- 🔒 Domain-named encrypted column types for text, integers, floats, numerics, dates, timestamps, booleans, and JSON — the name encodes the query capability (`cipherstash.TextSearch()`, `cipherstash.DoubleOrd()`, …)
- 🔍 Searchable encryption — equality, free-text search, range, order, JSON path and containment
- 🎯 Type-safe query operators — the EQL-derived `eql*` vocabulary (`eqlEq`, `eqlMatch`, `eqlGt`, `eqlAsc`, …)
- ⚡ Bulk encrypt / bulk decrypt coalescing — one SDK round-trip per `(table, column)` group per query
- 🧩 One-call setup via `cipherstashFromStack({ contractJson })` — no duplicate stack schema to maintain
- 🛡️ Plaintext redaction on every implicit serialisation path (`toJSON`, `toString`, `util.inspect`, …)

## Installation

```bash
npm install @cipherstash/stack @cipherstash/stack-prisma
```

## Quick start

```prisma
// prisma/schema.prisma
model User {
  id            String @id
  email         cipherstash.TextSearch()
  salary        cipherstash.DoubleOrd()
  birthday      cipherstash.DateOrd()
  preferences   cipherstash.Json()
}
```

```typescript
// prisma-next.config.ts
import cipherstash from "@cipherstash/stack-prisma/control"
import { defineConfig } from "@prisma/orm-postgres/config"

export default defineConfig({
  contract: "./prisma/schema.prisma",
  output: "src/prisma",
  extensions: [cipherstash],
  db: { connection: process.env.DATABASE_URL! },
})
```

```typescript
// src/db.ts
import "dotenv/config"
import { cipherstashFromStack } from "@cipherstash/stack-prisma/v3"
import postgres from "@prisma/orm-postgres/runtime"
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
npx prisma-next migrate                   # installs EQL bundle + your schema (top-level `migrate`, not `migration apply`)
```

```typescript
import { EncryptedString, decryptAll } from "@cipherstash/stack-prisma/runtime"

await db.orm.public.User.create({
  id: "user-0",
  email: EncryptedString.from("alice@example.com"),
  // ...
})

const rows = await db.orm.public.User
  .where((u) => u.email.eqlMatch("example.com"))
  .all()

await decryptAll(rows)
console.log(await rows[0]?.email.decrypt())
```

See the [full documentation](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) for the complete encrypted column reference, all 23 query operators (including encrypted JSONPath comparisons), the override surface, security model, and known limitations.

## Subpath exports

| Subpath          | Purpose                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------------------ |
| `./v3`           | The complete EQL v3 surface: `cipherstashFromStack`, the `eql*` query operations, `eqlAsc`/`eqlDesc`, `eqlJsonPathAsc`/`eqlJsonPathDesc`, envelopes, `bulkEncryptMiddlewareV3`, SDK adapter |
| `./stack`        | One-call setup against `@cipherstash/stack`: `cipherstashFromStack`, `deriveStackSchemasV3`, `createCipherstashV3Sdk` |
| `./control`      | `SqlControlExtensionDescriptor` (contract space + pack meta + v3 codec lifecycle hooks)                |
| `./runtime`      | Envelope classes + `CipherstashSdk` + v3 codec runtime + `decryptAll` + `bulkEncryptMiddlewareV3`      |
| `./pack`         | `cipherstashPackMeta` for TS contract authoring                                                        |
| `./column-types` | The v3 domain factories: `text` / `textSearch` / `integerOrd` / `bigIntOrd` / `date` / `boolean` / `json` / … |

`./control` and `./runtime` are tree-shakable. `./stack` sits on top of `./runtime` and additionally pulls in `@cipherstash/stack`; consumers who implement `CipherstashSdk` against a different KMS skip `./stack` and pay no `@cipherstash/stack` bundle cost.

## Authentication

There are 2 main ways to authenticate to CipherStash:

### Local profile (Dev)

`npx stash auth login` lets you log in via the browser and saves credentials in the CipherStash profile (`~/.cipherstash`). A key is automatically generated and granted access to the default keyset.

### Env vars (Production)

The four `CS_*` env vars (`CS_WORKSPACE_CRN`, `CS_CLIENT_ID`, `CS_CLIENT_KEY`, `CS_CLIENT_ACCESS_KEY`) are reserved for production deployments and CI runners. See the [authentication docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next#authentication) for more information.

## Example

A runnable end-to-end example lives at [`examples/prisma/`](https://github.com/cipherstash/stack/tree/main/examples/prisma) — bundles a docker-compose Postgres, a six-codec `User` schema, and a flow that exercises every operator category against a live ZeroKMS workspace.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-dark.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-dark.svg">
    <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-light.svg">
    <img alt="CipherStash architecture: encryption and decryption happen in your TypeScript app; only ciphertext (EQL JSON) is stored in your PostgreSQL database. ZeroKMS issues a unique key per value, derived in your app. Plaintext and keys never reach CipherStash, and every decryption is logged for audit." width="880" src="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-light.svg">
  </picture>
</p>

Encryption happens in your application: the codecs encrypt on write and the `eql*` operators encrypt
their query operands, so only ciphertext ([EQL](https://github.com/cipherstash/encrypt-query-language)
payloads in `eql_v3_*` column domains) ever reaches Postgres. Per-value keys are issued in bulk by
[ZeroKMS](https://cipherstash.com/docs/stack/cipherstash/kms?utm_source=github&utm_medium=stack_prisma_readme),
plaintext and keys never reach CipherStash, and every decryption is logged for audit.

## Contributing

See [`DEVELOPING.md`](https://github.com/cipherstash/stack/blob/main/packages/stack-prisma/DEVELOPING.md) for the source layout, two-pass codec encode + middleware rewrite lifecycle, physical-column-name routing, the `bigint → Number` SDK boundary, and other runtime-side details.

## References

- 📖 [**Full docs**](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) — column types, operator reference, security model, known limitations.
- [CipherStash EQL reference](https://cipherstash.com/docs/stack/platform/eql) — encrypted operator semantics and search-config index types.
- [`@cipherstash/stack`](https://www.npmjs.com/package/@cipherstash/stack) — encryption SDK and schema DSL.
- [Prisma Next](https://www.npmjs.com/package/prisma-next) — the framework this extension plugs into.

## License

MIT
