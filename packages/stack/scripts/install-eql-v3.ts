import { config } from 'dotenv'

// Load env files in Next.js precedence order (.env.local wins over .env for the
// same key, since dotenv does not overwrite already-set vars). `quiet: true`
// suppresses dotenv v17's `injected env (N) from …` banner so this script does
// not print noisy, non-deterministic lines in CI. Mirrors the CLI entrypoint
// (packages/cli/src/bin/main.ts).
config({ path: '.env.local', quiet: true })
config({ path: '.env.development.local', quiet: true })
config({ path: '.env.development', quiet: true })
config({ path: '.env', quiet: true })

import postgres from 'postgres'
import { installEqlV3IfNeeded } from '../__tests__/helpers/eql-v3'

if (!process.env.DATABASE_URL) {
  throw new Error('Missing env.DATABASE_URL')
}

const sql = postgres(process.env.DATABASE_URL, { prepare: false })

try {
  await installEqlV3IfNeeded(sql)
  console.log('eql_v3.text_search is installed')
} finally {
  await sql.end()
}
