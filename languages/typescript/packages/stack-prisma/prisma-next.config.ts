/**
 * Prisma Next config for the `@cipherstash/stack-prisma` package itself.
 *
 * The extension package is treated as a self-contained "project" for
 * the CLI: `prisma-next contract emit` writes
 * `src/contract.{json,d.ts}` (colocated with the `src/contract.prisma`
 * source); the migration self-emit script
 * (`pnpm tsx migrations/<dirName>/migration.ts`) re-emits
 * `migrations/<dirName>/{ops,migration}.json` from the hand-edited
 * `migration.ts` subclass.
 *
 * This config is **maintainer-only** — application authors who consume
 * this package do not need it. Their own `prisma-next.config.ts`
 * registers the extension via `extensions: [cipherstash]`; the
 * descriptor at `src/exports/control.ts` JSON-imports the on-disk
 * artefacts emitted here.
 */

import { prismaContract } from '@prisma/orm-family-sql/contract-psl/provider'
import sql from '@prisma/orm-family-sql/family/control'
import postgresAdapter from '@prisma/orm-target-postgres/adapter/control'
import postgres from '@prisma/orm-target-postgres/target/control'
import { postgresCreateNamespace } from '@prisma/orm-target-postgres/target/types'
import { defineConfig } from '@prisma/orm-toolchain/cli/config-types'

export default defineConfig({
  family: sql,
  target: postgres,
  adapter: postgresAdapter,
  contract: prismaContract('./src/contract.prisma', {
    output: 'src/contract.json',
    target: postgres,
    // Since 0.15 the SQL family no longer materialises a placeholder
    // namespace, so the target's namespace factory is required.
    createNamespace: postgresCreateNamespace,
  }),
  migrations: {
    dir: 'migrations',
  },
})
