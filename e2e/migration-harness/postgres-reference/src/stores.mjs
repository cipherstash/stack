import postgres from 'postgres'

export async function createStores(env = process.env) {
  if (!env.DATABASE_URL) throw Error('Missing DATABASE_URL')
  const database = new URL(env.DATABASE_URL)
  if (!['localhost', '127.0.0.1', '[::1]'].includes(database.hostname))
    throw Error('Fixture store must be local')
  const sql = postgres(env.DATABASE_URL, { prepare: false, onnotice: () => {} })
  return { sql, init: async () => {}, close: () => sql.end() }
}
