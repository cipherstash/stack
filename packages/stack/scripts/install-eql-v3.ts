import 'dotenv/config'
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
