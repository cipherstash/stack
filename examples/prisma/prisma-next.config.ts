import 'dotenv/config'
import cipherstash from '@cipherstash/stack-prisma/control'
import { defineConfig } from '@prisma/orm-postgres/config'

const databaseUrl = process.env['DATABASE_URL']

export default defineConfig({
  // Since 0.17 an application depends on exactly one database facade
  // (`@prisma/orm-postgres`); its `defineConfig` wires the family,
  // target, adapter, driver, and PSL provider internally.
  contract: './prisma/schema.prisma',
  output: 'src/prisma',
  extensions: [cipherstash],
  migrations: {
    dir: 'migrations',
  },
  // `contract emit` does not need a database connection; only
  // `prisma-next migrate` does. We pass `connection` through when
  // `DATABASE_URL` is set so the same config supports every CLI
  // subcommand, and let `prisma-next migrate` error explicitly if the
  // connection is missing.
  ...(databaseUrl ? { db: { connection: databaseUrl } } : {}),
})
