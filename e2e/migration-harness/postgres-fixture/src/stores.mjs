import postgres from 'postgres'

export async function createStores(env = process.env) {
  if (!env.DATABASE_URL) throw Error('Missing DATABASE_URL')
  const database = new URL(env.DATABASE_URL)
  if (!['localhost', '127.0.0.1', '[::1]'].includes(database.hostname))
    throw Error('Fixture store must be a local disposable database')
  const sql = postgres(env.DATABASE_URL, { prepare: false, onnotice: () => {} })
  return {
    sql,
    async init() {
      await sql`CREATE TABLE IF NOT EXISTS customers (
        pk text PRIMARY KEY,
        email public.eql_v2_encrypted,
        age public.eql_v2_encrypted,
        notes public.eql_v2_encrypted
      )`
    },
    close: () => sql.end(),
  }
}
