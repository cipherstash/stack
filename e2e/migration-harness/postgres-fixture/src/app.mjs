import { csColumn, csTable, protect } from '@cipherstash/protect'
import { createStores } from './stores.mjs'

const customers = csTable('customers', {
  email: csColumn('email').equality(),
  age: csColumn('age').dataType('number').equality(),
  notes: csColumn('notes'),
})
const columns = ['email', 'age', 'notes']
function unwrap(result) {
  if (result.failure) throw Error('Legacy encryption operation failed')
  return result.data
}
export async function createApp(env = process.env) {
  for (const name of [
    'CS_WORKSPACE_CRN',
    'CS_CLIENT_ID',
    'CS_CLIENT_KEY',
    'CS_CLIENT_ACCESS_KEY',
  ])
    if (!env[name]) throw Error(`Missing ${name}`)
  const region = env.CS_WORKSPACE_CRN.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST =
    env.CS_CTS_HOST ?? `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST =
    env.CS_ZEROKMS_HOST ?? `https://${region}.viturhosted.net`
  let client
  try {
    client = await protect({
      schemas: [customers],
      workspaceCrn: env.CS_WORKSPACE_CRN,
      clientId: env.CS_CLIENT_ID,
      clientKey: env.CS_CLIENT_KEY,
      accessKey: env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  }
  const stores = await createStores(env)
  const { sql } = stores
  async function decrypt(row) {
    if (!row) return null
    const values = await Promise.all(
      columns.map(async (column) => [
        column,
        unwrap(await client.decrypt(row[column])),
      ]),
    )
    return { pk: row.pk, ...Object.fromEntries(values) }
  }
  async function find(column, value) {
    if (!['email', 'age'].includes(column)) throw Error('Unsupported lookup')
    const term = unwrap(
      await client.encrypt(value, {
        table: customers,
        column: customers[column],
      }),
    )
    const rows =
      await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes
      FROM customers WHERE ${sql(column)} = ${sql.json(term)}::jsonb ORDER BY pk`
    return Promise.all(rows.map(decrypt))
  }
  return {
    async put(customer) {
      if (
        typeof customer.pk !== 'string' ||
        typeof customer.email !== 'string' ||
        typeof customer.notes !== 'string' ||
        !Number.isSafeInteger(customer.age)
      )
        throw Error('Unsupported customer')
      const encrypted = Object.fromEntries(
        await Promise.all(
          columns.map(async (column) => [
            column,
            unwrap(
              await client.encrypt(customer[column], {
                table: customers,
                column: customers[column],
              }),
            ),
          ]),
        ),
      )
      await sql`INSERT INTO customers (pk, email, age, notes) VALUES
        (${customer.pk}, ${sql.json(encrypted.email)}, ${sql.json(encrypted.age)}, ${sql.json(encrypted.notes)})`
    },
    async get(pk) {
      const rows =
        await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM customers WHERE pk = ${pk}`
      return decrypt(rows[0])
    },
    findEmail: (value) => find('email', value),
    findAge: (value) => find('age', value),
    close: () => stores.close(),
  }
}
