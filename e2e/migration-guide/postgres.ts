import { csColumn, csTable } from '@cipherstash/protect'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import type postgres from 'postgres'
import { legacyProtect, ok } from './legacy.ts'

/** A deliberately small migration example, not a general backfill service. */
export async function createExample(sql: postgres.Sql, table: string) {
  if (!/^[a-z][a-z0-9_]{0,39}$/.test(table))
    throw new Error('Invalid example table name')
  const legacySchema = csTable('customers', {
    email: csColumn('email').equality(),
    age: csColumn('age').dataType('number').equality(),
    notes: csColumn('notes'),
  })
  const schema = encryptedTable('customers', {
    email: types.TextEq('email'),
    age: types.IntegerEq('age'),
    notes: types.Text('notes'),
  })
  const legacy = await legacyProtect([legacySchema])
  const stack = await Encryption({ schemas: [schema] })
  const columns = ['email', 'age', 'notes'] as const
  const corpus = [
    { pk: 'ada', email: 'ada@example.com', age: 36, notes: 'engines' },
    { pk: 'alan', email: 'alan@example.com', age: 36, notes: 'machines' },
    { pk: 'grace', email: 'grace@example.com', age: 85, notes: 'compilers' },
  ]

  async function seed() {
    // Never replace an existing table or seed a customer's database in place.
    await sql.begin(async (tx) => {
      await tx`CREATE TABLE ${tx(table)} (
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
        await tx`INSERT INTO ${tx(table)} VALUES (${row.pk}, ${tx.json(email)}, ${tx.json(age)}, ${tx.json(notes)})`
      }
    })
  }

  async function read(generation: 'v2' | 'v3') {
    // Custom domain OIDs are not JSON parser OIDs in postgres.js. Project the
    // base jsonb type explicitly instead of passing serialized text to the SDK.
    const rows =
      generation === 'v2'
        ? await sql`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${sql(table)} ORDER BY pk`
        : await sql`SELECT pk, email_v3::jsonb AS email, age_v3::jsonb AS age, notes_v3::jsonb AS notes FROM ${sql(table)} ORDER BY pk`
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
        ? await sql`SELECT pk FROM ${sql(table)} WHERE ${sql(column)} = ${sql.json(jsonTerm)}::jsonb ORDER BY pk`
        : column === 'email'
          ? await sql`SELECT pk FROM ${sql(table)} WHERE eql_v3.eq(email_v3, ${sql.json(jsonTerm)}::jsonb::eql_v3.query_text_eq) ORDER BY pk`
          : await sql`SELECT pk FROM ${sql(table)} WHERE eql_v3.eq(age_v3, ${sql.json(jsonTerm)}::jsonb::eql_v3.query_integer_eq) ORDER BY pk`
    return rows.map((row) => row.pk)
  }

  async function checkDependencies(
    tx: postgres.TransactionSql,
    allowTargetIndexes: boolean,
  ) {
    const dependencies = await tx`SELECT
      EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = ${table}::regclass AND NOT tgisinternal)
      OR EXISTS (SELECT 1 FROM pg_constraint WHERE (conrelid = ${table}::regclass OR confrelid = ${table}::regclass)
        AND (contype <> 'p' OR conkey <> ARRAY[1]::smallint[]))
      OR EXISTS (SELECT 1 FROM pg_index ix JOIN pg_class idx ON idx.oid = ix.indexrelid
        WHERE indrelid = ${table}::regclass AND NOT indisprimary AND NOT (
          ${allowTargetIndexes} AND NOT indisunique AND indpred IS NULL AND indnatts = 1
          AND ((idx.relname = ${`${table}_email_v3_idx`} AND pg_get_indexdef(indexrelid, 1, true) = 'eql_v3.eq_term(email_v3)')
            OR (idx.relname = ${`${table}_age_v3_idx`} AND pg_get_indexdef(indexrelid, 1, true) = 'eql_v3.eq_term(age_v3)'))))
      OR EXISTS (SELECT 1 FROM pg_depend WHERE refobjid = ${table}::regclass AND classid = 'pg_rewrite'::regclass)
      OR (SELECT relrowsecurity OR relispartition OR relkind <> 'r' FROM pg_class WHERE oid = ${table}::regclass)
      OR EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = ${table}::regclass)
      OR EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = ${table}::regclass OR inhrelid = ${table}::regclass)
      AS unsupported`
    if (dependencies[0].unsupported)
      throw new Error(
        'Unsupported table dependencies: review constraints, indexes, views, triggers, policies and inheritance first',
      )
  }

  async function migrate() {
    await sql.begin(async (tx) => {
      await tx`LOCK TABLE ${tx(table)} IN ACCESS EXCLUSIVE MODE`
      // Fail before adding any columns. This example understands one exact shape.
      const attributes =
        await tx`SELECT attname, atttypid::regtype::text AS type
        FROM pg_attribute WHERE attrelid = ${table}::regclass
          AND attnum > 0 AND NOT attisdropped ORDER BY attnum`
      if (
        JSON.stringify(attributes.map((a) => [a.attname, a.type])) !==
        JSON.stringify([
          ['pk', 'text'],
          ['email', 'eql_v2_encrypted'],
          ['age', 'eql_v2_encrypted'],
          ['notes', 'eql_v2_encrypted'],
        ])
      )
        throw new Error(
          'Unsupported columns: expected pk and three EQL v2 columns',
        )
      await checkDependencies(tx, false)
      const rows =
        await tx`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${tx(table)} ORDER BY pk`
      if (rows.length === 0)
        throw new Error('Empty source: this example requires legacy records')
      for (const row of rows) {
        for (const column of columns) {
          const payload = row[column]
          if (
            payload?.v !== 2 ||
            payload.k !== 'ct' ||
            typeof payload.c !== 'string' ||
            payload.i?.t !== 'customers' ||
            payload.i?.c !== column ||
            Object.keys(payload).some(
              (key) => !['v', 'k', 'i', 'c', 'hm'].includes(key),
            ) ||
            (column === 'notes'
              ? payload.hm !== undefined
              : typeof payload.hm !== 'string')
          ) {
            throw new Error(`Unsupported legacy payload in ${column}`)
          }
          const plain = ok(
            await legacy.decrypt(payload),
            'validate legacy payload',
          )
          if (
            column === 'age'
              ? !Number.isSafeInteger(plain)
              : typeof plain !== 'string'
          ) {
            throw new Error(`Unsupported plaintext in ${column}`)
          }
          if (column !== 'notes') {
            const term =
              column === 'email'
                ? ok(
                    await stack.encryptQuery(String(plain), {
                      table: schema,
                      column: schema.email,
                    }),
                    'verify email mapping',
                  )
                : ok(
                    await stack.encryptQuery(Number(plain), {
                      table: schema,
                      column: schema.age,
                    }),
                    'verify age mapping',
                  )
            if (
              typeof term !== 'object' ||
              term === null ||
              !('hm' in term) ||
              term.hm !== payload.hm
            ) {
              throw new Error(`Unsupported equality mapping in ${column}`)
            }
          }
        }
      }
      await tx`ALTER TABLE ${tx(table)}
        ADD COLUMN email_v3 public.eql_v3_text_eq,
        ADD COLUMN age_v3 public.eql_v3_integer_eq,
        ADD COLUMN notes_v3 public.eql_v3_text`
      // Rebuild only the envelope. Source columns and their bytes stay intact.
      for (const column of columns) {
        await tx`UPDATE ${tx(table)} SET ${tx(`${column}_v3`)} = jsonb_build_object(
          'v', 3, 'i', ${tx(column)}::jsonb->'i', 'c', ${tx(column)}::jsonb->'c'
        ) || CASE WHEN ${column} = 'notes' THEN '{}'::jsonb
          ELSE jsonb_build_object('hm', ${tx(column)}::jsonb->'hm') END`
      }
      await tx`CREATE INDEX ${tx(`${table}_email_v3_idx`)} ON ${tx(table)} (eql_v3.eq_term(email_v3))`
      await tx`CREATE INDEX ${tx(`${table}_age_v3_idx`)} ON ${tx(table)} (eql_v3.eq_term(age_v3))`
      // Read through Stack before committing, so a wrong mapping rolls back DDL too.
      const converted =
        await tx`SELECT pk, email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3, notes_v3::jsonb AS notes_v3 FROM ${tx(table)} ORDER BY pk`
      for (let i = 0; i < rows.length; i++) {
        for (const column of columns) {
          const before = rows[i][column]
          const after = converted[i][`${column}_v3`]
          if (
            after.c !== before.c ||
            after.hm !== before.hm ||
            ok(await stack.decrypt(after), 'verify target') !==
              ok(await legacy.decrypt(before), 'verify source')
          ) {
            throw new Error(`Conversion verification failed in ${column}`)
          }
        }
      }
    })
    await sql`ANALYZE ${sql(table)}`
  }

  async function write() {
    const model = {
      pk: 'new',
      email: 'new@example.com',
      age: 36,
      notes: 'written by Stack',
    }
    const encrypted = ok(await stack.encryptModel(model, schema), 'fresh write')
    await sql`INSERT INTO ${sql(table)} (pk, email_v3, age_v3, notes_v3)
      VALUES (${model.pk}, ${sql.json(encrypted.email)}, ${sql.json(encrypted.age)}, ${sql.json(encrypted.notes)})`
    return model
  }

  async function rollback() {
    await sql.begin(async (tx) => {
      await tx`LOCK TABLE ${tx(table)} IN ACCESS EXCLUSIVE MODE`
      await checkDependencies(tx, true)
      const rows =
        await tx`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes,
        email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3, notes_v3::jsonb AS notes_v3 FROM ${tx(table)}`
      for (const row of rows) {
        for (const column of columns) {
          if (
            !row[column] ||
            !row[`${column}_v3`] ||
            row[column].c !== row[`${column}_v3`].c ||
            row[column].hm !== row[`${column}_v3`].hm
          ) {
            throw new Error(
              'Writes have resumed: reconcile target changes before rollback',
            )
          }
        }
      }
      // Preflight permits only our two derived indexes. PostgreSQL otherwise
      // drops same-table constraints/indexes with a column even without CASCADE.
      await tx`ALTER TABLE ${tx(table)} DROP COLUMN email_v3, DROP COLUMN age_v3, DROP COLUMN notes_v3`
    })
  }

  return { corpus, seed, migrate, read, find, write, rollback }
}
