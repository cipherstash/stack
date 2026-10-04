import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import pg from 'pg'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)
const sqlDir = resolve(__dirname, '..', '..', 'sql')

export const DEFAULT_DATABASE_URL =
  'postgres://cipherstash:password@localhost:5432/cipherstash'

export function getDatabaseUrl(): string {
  return process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL
}

export async function connect(): Promise<pg.Client> {
  const client = new pg.Client({ connectionString: getDatabaseUrl() })
  await client.connect()
  return client
}

export async function applySchema(client: pg.Client): Promise<void> {
  const path = resolve(sqlDir, 'schema.sql')
  const sql = await readFile(path, 'utf8')
  await client.query(sql)
}

export async function countBenchRows(client: pg.Client): Promise<number> {
  const res = await client.query<{ count: string }>(
    'SELECT count(*)::text FROM bench',
  )
  return Number(res.rows[0].count)
}
