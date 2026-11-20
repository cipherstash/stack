import type postgres from 'postgres'
import {
  createConversion,
  createMigrationClients,
  ok,
} from './postgres-conversion.ts'

/** A deliberately small migration example, not a general backfill service. */
export async function createExample(sql: postgres.Sql, table: string) {
  if (!/^[a-z][a-z0-9_]{0,39}$/.test(table))
    throw new Error('Invalid example table name')
  const clients = createMigrationClients()
  const { legacySchema, schema, legacy, stack, columns } = await clients
  const { migrate, checkDependencies } = await createConversion(
    sql,
    table,
    clients,
  )
  const relation = `public.${table}`
  const corpus = [
    { pk: 'ada', email: 'ada@example.com', age: 36, notes: 'engines' },
    { pk: 'alan', email: 'alan@example.com', age: 36, notes: 'machines' },
    { pk: 'grace', email: 'grace@example.com', age: 85, notes: 'compilers' },
  ]

  async function seed() {
    // Never replace an existing table or seed a customer's database in place.
    await sql.begin(async (tx) => {
      await tx`CREATE TABLE ${tx(relation)} (
        pk text PRIMARY KEY,
        email public.eql_v2_encrypted,
        age public.eql_v2_encrypted,
        notes public.eql_v2_encrypted
      )`
      for (const row of corpus) {
        const email = ok(
          await legacy.encrypt(row.email, {
            table: legacySchema,
            column: legacySchema.email,
          }),
          'legacy email',
        )
        const age = ok(
          await legacy.encrypt(row.age, {
            table: legacySchema,
            column: legacySchema.age,
          }),
          'legacy age',
        )
        const notes = ok(
          await legacy.encrypt(row.notes, {
            table: legacySchema,
            column: legacySchema.notes,
          }),
          'legacy notes',
        )
        await tx`INSERT INTO ${tx(relation)} VALUES (${row.pk}, ${tx.json(email)}, ${tx.json(age)}, ${tx.json(notes)})`
      }
    })
  }

  async function read(generation: 'v2' | 'v3') {
    // Custom domain OIDs are not JSON parser OIDs in postgres.js. Project the
    // base jsonb type explicitly instead of passing serialized text to the SDK.
    const rows =
      generation === 'v2'
        ? await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${sql(relation)} ORDER BY pk`
        : await sql`SELECT pk, email_v3::jsonb AS email, age_v3::jsonb AS age, notes_v3::jsonb AS notes FROM ${sql(relation)} ORDER BY pk`
    return Promise.all(
      rows.map(async (row) => {
        const values = await Promise.all(
          columns.map(async (column) => {
            const payload = row[column]
            return [
              column,
              ok(
                await (generation === 'v2'
                  ? legacy.decrypt(payload)
                  : stack.decrypt(payload)),
                'decrypt',
              ),
            ] as const
          }),
        )
        return { pk: row.pk, ...Object.fromEntries(values) }
      }),
    )
  }

  async function find(
    generation: 'v2' | 'v3',
    column: 'email' | 'age',
    value: string | number,
  ) {
    if (
      (column === 'email' && typeof value !== 'string') ||
      (column === 'age' && !Number.isSafeInteger(value))
    ) {
      throw new Error('Unsupported query value')
    }
    // Protect's encrypt output includes the equality term used by its SQL operator.
    const term =
      generation === 'v2'
        ? ok(
            await legacy.encrypt(value, {
              table: legacySchema,
              column: legacySchema[column],
            }),
            'legacy term',
          )
        : column === 'email'
          ? ok(
              await stack.encryptQuery(String(value), {
                table: schema,
                column: schema.email,
              }),
              'email term',
            )
          : ok(
              await stack.encryptQuery(Number(value), {
                table: schema,
                column: schema.age,
              }),
              'age term',
            )
    // The SDK's query result union also includes non-JSON query families.
    // This equality example binds the actual JSON wire representation.
    const jsonTerm: postgres.JSONValue = JSON.parse(JSON.stringify(term))
    const rows =
      generation === 'v2'
        ? await sql`SELECT pk FROM ${sql(relation)} WHERE ${sql(column)} = ${sql.json(jsonTerm)}::jsonb ORDER BY pk`
        : column === 'email'
          ? await sql`SELECT pk FROM ${sql(relation)} WHERE eql_v3.eq(email_v3, ${sql.json(jsonTerm)}::jsonb::eql_v3.query_text_eq) ORDER BY pk`
          : await sql`SELECT pk FROM ${sql(relation)} WHERE eql_v3.eq(age_v3, ${sql.json(jsonTerm)}::jsonb::eql_v3.query_integer_eq) ORDER BY pk`
    return rows.map((row) => row.pk)
  }

  async function write() {
    const model = {
      pk: 'new',
      email: 'new@example.com',
      age: 36,
      notes: 'written by Stack',
    }
    const encrypted = ok(await stack.encryptModel(model, schema), 'fresh write')
    await sql`INSERT INTO ${sql(relation)} (pk, email_v3, age_v3, notes_v3)
      VALUES (${model.pk}, ${sql.json(encrypted.email)}, ${sql.json(encrypted.age)}, ${sql.json(encrypted.notes)})`
    return model
  }

  async function rollback() {
    await sql.begin(async (tx) => {
      await tx`LOCK TABLE ${tx(relation)} IN ACCESS EXCLUSIVE MODE`
      await checkDependencies(tx, true)
      const rows =
        await tx`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes,
        email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3, notes_v3::jsonb AS notes_v3 FROM ${tx(relation)}`
      for (const row of rows) {
        for (const column of columns) {
          if (
            !row[column] ||
            !row[`${column}_v3`] ||
            row[column].c !== row[`${column}_v3`].c ||
            (row[column].hm ?? null) !== (row[`${column}_v3`].hm ?? null)
          ) {
            throw new Error(
              'Writes have resumed: reconcile target changes before rollback',
            )
          }
        }
      }
      // Preflight permits only our two derived indexes. PostgreSQL otherwise
      // drops same-table constraints/indexes with a column even without CASCADE.
      await tx`ALTER TABLE ${tx(relation)} DROP COLUMN email_v3, DROP COLUMN age_v3, DROP COLUMN notes_v3`
    })
  }

  return { corpus, seed, migrate, read, find, write, rollback }
}
