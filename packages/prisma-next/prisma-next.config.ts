/**
 * Prisma Next config for the `@cipherstash/prisma-next` package itself.
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
 * registers the extension via `extensionPacks: [cipherstash]`; the
 * descriptor at `src/exports/control.ts` JSON-imports the on-disk
 * artefacts emitted here.
 */

import postgresAdapter from '@prisma-next/adapter-postgres/control'
import { defineConfig } from '@prisma-next/cli/config-types'
import sql from '@prisma-next/family-sql/control'
import { prismaContract } from '@prisma-next/sql-contract-psl/provider'
import postgres from '@prisma-next/target-postgres/control'

export default defineConfig({
  family: sql,
  target: postgres,
  adapter: postgresAdapter,
  contract: prismaContract('./src/contract.prisma', {
    output: 'src/contract.json',
    target: postgres,
  }),
  migrations: {
    dir: 'migrations',
  },
})
