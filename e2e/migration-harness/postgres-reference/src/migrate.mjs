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

/** One-off conversion run during the write-maintenance window, before the
 * migrated application starts. createApp never alters the schema. */
export async function migrate(env = process.env) {
  const client = await Encryption({ schemas: [customers] })
  const stores = await createStores(env)
  const { sql } = stores
  try {
    // This conversion runs only inside App Host, using that actor's independent
    // Store Set. It follows the guide's three supported mappings and retains
    // sources. A rerun finds the target columns and changes nothing.
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
  } finally {
    await stores.close()
  }
}
