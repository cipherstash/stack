import 'dotenv/config'
import postgresAdapter from '@prisma-next/adapter-postgres/control'
import { defineConfig } from '@prisma-next/cli/config-types'
import postgresDriver from '@prisma-next/driver-postgres/control'
import sql from '@prisma-next/family-sql/control'
import { prismaContract } from '@prisma-next/sql-contract-psl/provider'
import postgres from '@prisma-next/target-postgres/control'
import cipherstash from '@cipherstash/prisma-next/control'

const databaseUrl = process.env['DATABASE_URL']

export default defineConfig({
  family: sql,
  target: postgres,
  driver: postgresDriver,
  adapter: postgresAdapter,
  extensionPacks: [cipherstash],
  contract: prismaContract('./prisma/schema.prisma', {
    output: 'src/prisma/contract.json',
    target: postgres,
  }),
  migrations: {
    dir: 'migrations',
  },
  // `contract emit` does not need a database connection; only
  // `migration apply` does. We pass `connection` through when
  // `DATABASE_URL` is set so the same config supports every CLI
  // subcommand, and let `migration apply` error explicitly if the
  // connection is missing.
  ...(databaseUrl ? { db: { connection: databaseUrl } } : {}),
})
