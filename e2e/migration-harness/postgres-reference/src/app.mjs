import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { createStores } from './stores.mjs'

const variant = 'reference'
const customers = encryptedTable('customers', {
  email: types.TextEq('email'),
  age: types.IntegerEq('age'),
  notes: types.Text('notes'),
})
const columns = ['email', 'age', 'notes']
function unwrap(result) {
  if (result.failure) throw Error('Stack encryption operation failed')
  return result.data
}

export async function createApp(env = process.env) {
  const client = await Encryption({ schemas: [customers] })
  const stores = await createStores(env)
  const { sql } = stores
  async function decrypt(row) {
    if (!row) return null
    return {
      pk: row.pk,
      ...Object.fromEntries(
        await Promise.all(
          columns.map(async (column) => [
            column,
            unwrap(await client.decrypt(row[column])),
          ]),
        ),
      ),
    }
  }
  return {
    async get(pk) {
      if (variant === 'fresh-v2') {
        const rows =
          await sql`SELECT pk, coalesce(email_v3::jsonb, email::jsonb) AS email, coalesce(age_v3::jsonb, age::jsonb) AS age, coalesce(notes_v3::jsonb, notes::jsonb) AS notes FROM customers WHERE pk = ${pk}`
        return decrypt(rows[0])
      }
      const rows =
        await sql`SELECT pk, email_v3::jsonb AS email, age_v3::jsonb AS age, notes_v3::jsonb AS notes FROM customers WHERE pk = ${pk}`
      return decrypt(rows[0])
    },
    async findEmail(value) {
      if (variant === 'fresh-v2') {
        const rows =
          await sql`SELECT pk, coalesce(email_v3::jsonb, email::jsonb) AS email, coalesce(age_v3::jsonb, age::jsonb) AS age, coalesce(notes_v3::jsonb, notes::jsonb) AS notes FROM customers ORDER BY pk`
        return (await Promise.all(rows.map(decrypt))).filter(
          (row) => row.email === value,
        )
      }
      const term = unwrap(
        await client.encryptQuery(value, {
          table: customers,
          column: customers.email,
        }),
      )
      const rows =
        await sql`SELECT pk, email_v3::jsonb AS email, age_v3::jsonb AS age, notes_v3::jsonb AS notes FROM customers
        WHERE eql_v3.eq(email_v3, ${sql.json(term)}::jsonb::eql_v3.query_text_eq) ORDER BY pk`
      return Promise.all(rows.map(decrypt))
    },
    async findAge(value) {
      if (variant === 'fresh-v2') {
        const rows =
          await sql`SELECT pk, coalesce(email_v3::jsonb, email::jsonb) AS email, coalesce(age_v3::jsonb, age::jsonb) AS age, coalesce(notes_v3::jsonb, notes::jsonb) AS notes FROM customers ORDER BY pk`
        return (await Promise.all(rows.map(decrypt))).filter(
          (row) => row.age === value,
        )
      }
      if (variant === 'wrong-mapping') return []
      const term = unwrap(
        await client.encryptQuery(value, {
          table: customers,
          column: customers.age,
        }),
      )
      const rows =
        await sql`SELECT pk, email_v3::jsonb AS email, age_v3::jsonb AS age, notes_v3::jsonb AS notes FROM customers
        WHERE eql_v3.eq(age_v3, ${sql.json(term)}::jsonb::eql_v3.query_integer_eq) ORDER BY pk`
      return Promise.all(rows.map(decrypt))
    },
    async put(customer) {
      if (
        typeof customer.pk !== 'string' ||
        typeof customer.email !== 'string' ||
        typeof customer.notes !== 'string' ||
        !Number.isSafeInteger(customer.age)
      )
        throw Error('Unsupported customer')
      const model = unwrap(await client.encryptModel(customer, customers))
      if (variant === 'fresh-v2') {
        const old = Object.fromEntries(
          columns.map((column) => [
            column,
            {
              ...model[column],
              v: 2,
              k: 'ct',
              hm: model[column].hm ?? null,
              ob: null,
              bf: null,
            },
          ]),
        )
        await sql`INSERT INTO customers (pk, email, age, notes) VALUES (${model.pk}, ${sql.json(old.email)}, ${sql.json(old.age)}, ${sql.json(old.notes)})`
        return
      }
      await sql`INSERT INTO customers (pk, email_v3, age_v3, notes_v3) VALUES (${model.pk}, ${sql.json(model.email)}, ${sql.json(model.age)}, ${sql.json(model.notes)})`
    },
    close: () => stores.close(),
  }
}
