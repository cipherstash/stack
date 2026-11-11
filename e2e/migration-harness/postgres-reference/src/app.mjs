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
  try {
    // This conversion runs only inside App Host, using that actor's independent
    // Store Set. It follows the guide's three supported mappings and retains sources.
    await sql.begin(async (tx) => {
      await tx`LOCK TABLE customers IN ACCESS EXCLUSIVE MODE`
      const existing =
        await tx`SELECT 1 FROM pg_attribute WHERE attrelid = 'public.customers'::regclass AND attname = 'email_v3' AND NOT attisdropped`
      if (existing.length) return
      const rows =
        await tx`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM customers ORDER BY pk`
      for (const row of rows)
        for (const column of columns) {
          const source = row[column]
          if (
            source?.v !== 2 ||
            source.k !== 'ct' ||
            typeof source.c !== 'string' ||
            source.i?.t !== 'customers' ||
            source.i?.c !== column ||
            source.ob != null ||
            source.bf != null ||
            (column === 'notes'
              ? source.hm != null
              : typeof source.hm !== 'string')
          )
            throw Error('Unsupported legacy payload')
          const target = {
            v: 3,
            i: source.i,
            c: source.c,
            ...(column === 'notes' ? {} : { hm: source.hm }),
          }
          const plain = unwrap(await client.decrypt(target))
          if (
            column === 'age'
              ? !Number.isSafeInteger(plain)
              : typeof plain !== 'string'
          )
            throw Error('Unsupported plaintext')
          if (column !== 'notes') {
            const term = unwrap(
              await client.encryptQuery(plain, {
                table: customers,
                column: customers[column],
              }),
            )
            if (term.hm !== source.hm)
              throw Error('Unsupported equality mapping')
          }
        }
      await tx`ALTER TABLE customers ADD COLUMN email_v3 public.eql_v3_text_eq,
        ADD COLUMN age_v3 public.eql_v3_integer_eq, ADD COLUMN notes_v3 public.eql_v3_text`
      for (const column of columns)
        await tx`UPDATE customers SET ${tx(`${column}_v3`)} =
        jsonb_build_object('v', 3, 'i', ${tx(column)}::jsonb->'i', 'c', ${tx(column)}::jsonb->'c') ||
        CASE WHEN ${column} = 'notes' THEN '{}'::jsonb ELSE jsonb_build_object('hm', ${tx(column)}::jsonb->'hm') END`
      await tx`CREATE INDEX customers_email_v3_idx ON customers (eql_v3.eq_term(email_v3))`
      if (variant !== 'missing-index')
        await tx`CREATE INDEX customers_age_v3_idx ON customers (eql_v3.eq_term(age_v3))`
      if (variant === 'row-loss')
        await tx`DELETE FROM customers WHERE pk = 'alan'`
      if (variant === 'rewrite') {
        const [row] =
          await tx`SELECT email_v3::jsonb AS email FROM customers WHERE pk = 'ada'`
        const value = unwrap(await client.decrypt(row.email))
        const encrypted = unwrap(
          await client.encrypt(value, {
            table: customers,
            column: customers.email,
          }),
        )
        await tx`UPDATE customers SET email_v3 = ${tx.json(encrypted)} WHERE pk = 'ada'`
      }
    })
    await sql`ANALYZE customers`
  } catch (error) {
    await stores.close()
    throw error
  }
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
