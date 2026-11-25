import { pathToFileURL } from 'node:url'
import { csColumn, csTable, protect } from '@cipherstash/protect'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import postgres from 'postgres'

/** Protect 10.2.1 needs explicit managed endpoints outside ap-southeast-2. */
export async function legacyProtect(
  schemas: Parameters<typeof protect>[0]['schemas'],
) {
  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn) throw new Error('CS_WORKSPACE_CRN is required')
  const region = crn.split(':')[1]
  const saved = {
    CS_CTS_HOST: process.env.CS_CTS_HOST,
    CS_ZEROKMS_HOST: process.env.CS_ZEROKMS_HOST,
  }
  process.env.CS_CTS_HOST = `https://${region}.cts.cipherstashmanaged.net`
  process.env.CS_ZEROKMS_HOST = `https://${region}.viturhosted.net`
  try {
    return await protect({
      schemas,
      workspaceCrn: crn,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
    })
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

/** Check every SDK result; never continue with a failed encryption operation. */
export function ok<T>(
  result: { data: T; failure?: undefined } | { failure: unknown },
  label: string,
): T {
  if ('failure' in result && result.failure !== undefined) {
    throw new Error(`${label} failed`, { cause: result.failure })
  }
  if ('data' in result) return result.data
  throw new Error(`${label} returned no data`)
}

export async function createMigrationClients() {
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
  return { legacySchema, schema, legacy, stack, columns }
}

/** Bulk success is not enough: reject missing, reordered or failed items. */
function verifiedBulk(
  items: readonly (
    | { id?: string; data: unknown }
    | { id?: string; error: unknown }
  )[],
  expected: number,
  label: string,
): unknown[] {
  if (items.length !== expected) throw new Error(`${label} bulk count mismatch`)
  return items.map((item, i) => {
    if (item.id !== String(i) || 'error' in item || !('data' in item))
      throw new Error(`${label} bulk item failed or reordered`)
    return item.data
  })
}

export async function createConversion(
  sql: postgres.Sql,
  table: string,
  clients = createMigrationClients(),
) {
  if (!/^[a-z][a-z0-9_]{0,39}$/.test(table))
    throw new Error('Invalid example table name')
  const relation = `public.${table}`
  const { legacy, stack, schema, columns } = await clients
  async function checkDependencies(
    tx: postgres.TransactionSql,
    allowTargetIndexes: boolean,
  ) {
    // pg_get_indexdef qualifies functions only when they are not visible.
    // Stabilize its rendering for our exact rollback-index check; SET LOCAL
    // restores the caller's search path when this transaction ends.
    await tx`SET LOCAL search_path = pg_catalog`
    const dependencies = await tx`SELECT
      NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid = ${relation}::regclass AND contype = 'p'
        AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = ${relation}::regclass AND attname = 'pk' AND NOT attisdropped)]::smallint[])
      OR EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = ${relation}::regclass AND NOT tgisinternal)
      OR EXISTS (SELECT 1 FROM pg_constraint WHERE (conrelid = ${relation}::regclass OR confrelid = ${relation}::regclass)
        -- PostgreSQL 18 also lists the primary key column's NOT NULL here.
        AND NOT (contype IN ('p', 'n') AND conrelid = ${relation}::regclass AND conkey = ARRAY[(SELECT attnum FROM pg_attribute WHERE attrelid = ${relation}::regclass AND attname = 'pk' AND NOT attisdropped)]::smallint[]))
      -- PostgreSQL 17 and earlier keep NOT NULL out of pg_constraint, so read
      -- it from the column on every version.
      OR EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid = ${relation}::regclass
        AND attnum > 0 AND attname <> 'pk' AND NOT attisdropped AND attnotnull)
      OR EXISTS (SELECT 1 FROM pg_index ix JOIN pg_class idx ON idx.oid = ix.indexrelid
        WHERE indrelid = ${relation}::regclass AND NOT indisprimary AND NOT (
          ${allowTargetIndexes} AND NOT indisunique AND indpred IS NULL AND indnatts = 1
          AND ((idx.relname = ${`${table}_email_v3_idx`} AND pg_get_indexdef(indexrelid, 1, true) = 'eql_v3.eq_term(email_v3)')
            OR (idx.relname = ${`${table}_age_v3_idx`} AND pg_get_indexdef(indexrelid, 1, true) = 'eql_v3.eq_term(age_v3)'))))
      OR EXISTS (SELECT 1 FROM pg_depend WHERE refobjid = ${relation}::regclass AND classid = 'pg_catalog.pg_rewrite'::regclass)
      OR (SELECT relrowsecurity OR relispartition OR relkind <> 'r' FROM pg_class WHERE oid = ${relation}::regclass)
      OR EXISTS (SELECT 1 FROM pg_policy WHERE polrelid = ${relation}::regclass)
      OR EXISTS (SELECT 1 FROM pg_inherits WHERE inhparent = ${relation}::regclass OR inhrelid = ${relation}::regclass)
      AS unsupported`
    if (dependencies[0].unsupported)
      throw new Error(
        'Unsupported table dependencies: review constraints, indexes, views, triggers, policies and inheritance first',
      )
  }

  async function migrate() {
    await sql.begin(async (tx) => {
      await tx`LOCK TABLE ${tx(relation)} IN ACCESS EXCLUSIVE MODE`
      // Fail before adding any columns. This example understands one exact shape.
      const attributes =
        await tx`SELECT attname, atttypid = CASE WHEN attname = 'pk' THEN 'pg_catalog.text'::regtype ELSE 'public.eql_v2_encrypted'::regtype END AS supported_type
        FROM pg_attribute WHERE attrelid = ${relation}::regclass
          AND attnum > 0 AND NOT attisdropped ORDER BY attnum`
      if (
        JSON.stringify(attributes.map((a) => [a.attname, a.supported_type])) !==
        JSON.stringify([
          ['pk', true],
          ['email', true],
          ['age', true],
          ['notes', true],
        ])
      )
        throw new Error(
          'Unsupported columns: expected pk and three EQL v2 columns',
        )
      await checkDependencies(tx, false)
      const rows =
        await tx`SELECT pk, email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${tx(relation)} ORDER BY pk`
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
              (key) => !['v', 'k', 'i', 'c', 'hm', 'ob', 'bf'].includes(key),
            ) ||
            // Protect represents unused index capabilities with null fields.
            payload.ob != null ||
            payload.bf != null ||
            (column === 'notes'
              ? payload.hm != null
              : typeof payload.hm !== 'string')
          ) {
            throw new Error(`Unsupported legacy payload in ${column}`)
          }
        }
      }
      const payloads = rows.flatMap((row) =>
        columns.map((column) => row[column]),
      )
      const sourcePlaintexts = verifiedBulk(
        ok(
          await legacy.bulkDecrypt(
            payloads.map((data, i) => ({ id: String(i), data })),
          ),
          'decrypt source',
        ),
        payloads.length,
        'Source',
      )
      for (const [i] of payloads.entries()) {
        const column = columns[i % columns.length]
        const plain = sourcePlaintexts[i]
        if (
          column === 'age'
            ? !Number.isSafeInteger(plain)
            : typeof plain !== 'string'
        )
          throw new Error(`Unsupported plaintext in ${column}`)
      }
      const terms = ok(
        await stack.encryptQuery(
          rows.flatMap((_row, i) => [
            {
              value: String(sourcePlaintexts[i * columns.length]),
              table: schema,
              column: schema.email,
            },
            {
              value: Number(sourcePlaintexts[i * columns.length + 1]),
              table: schema,
              column: schema.age,
            },
          ]),
        ),
        'verify equality mappings',
      )
      if (terms.length !== rows.length * 2)
        throw new Error('Equality term count mismatch')
      for (const [i, term] of terms.entries()) {
        const column = i % 2 === 0 ? 'email' : 'age'
        if (
          typeof term !== 'object' ||
          term === null ||
          !('hm' in term) ||
          term.hm !== rows[Math.floor(i / 2)][column].hm
        )
          throw new Error(`Unsupported equality mapping in ${column}`)
      }
      await tx`ALTER TABLE ${tx(relation)}
        ADD COLUMN email_v3 public.eql_v3_text_eq,
        ADD COLUMN age_v3 public.eql_v3_integer_eq,
        ADD COLUMN notes_v3 public.eql_v3_text`
      // Rebuild only the envelope. Source columns and their bytes stay intact.
      for (const column of columns) {
        await tx`UPDATE ${tx(relation)} SET ${tx(`${column}_v3`)} = jsonb_build_object(
          'v', 3, 'i', ${tx(column)}::jsonb->'i', 'c', ${tx(column)}::jsonb->'c'
        ) || CASE WHEN ${column} = 'notes' THEN '{}'::jsonb
          ELSE jsonb_build_object('hm', ${tx(column)}::jsonb->'hm') END`
      }
      await tx`CREATE INDEX ${tx(`${table}_email_v3_idx`)} ON ${tx(relation)} (eql_v3.eq_term(email_v3))`
      await tx`CREATE INDEX ${tx(`${table}_age_v3_idx`)} ON ${tx(relation)} (eql_v3.eq_term(age_v3))`
      // Read through Stack before committing, so a wrong mapping rolls back DDL too.
      const converted =
        await tx`SELECT pk, email_v3::jsonb AS email_v3, age_v3::jsonb AS age_v3, notes_v3::jsonb AS notes_v3 FROM ${tx(relation)} ORDER BY pk`
      if (
        converted.length !== rows.length ||
        converted.some((row, i) => row.pk !== rows[i].pk)
      )
        throw new Error('Conversion verification failed: row identity mismatch')
      const targets = converted.flatMap((row) =>
        columns.map((column) => row[`${column}_v3`]),
      )
      const targetPlaintexts = verifiedBulk(
        ok(
          await stack.bulkDecrypt(
            targets.map((data, i) => ({ id: String(i), data })),
          ),
          'decrypt target',
        ),
        targets.length,
        'Target',
      )
      for (const [i, after] of targets.entries()) {
        const before = payloads[i]
        if (
          after.c !== before.c ||
          (after.hm ?? null) !== (before.hm ?? null) ||
          targetPlaintexts[i] !== sourcePlaintexts[i]
        )
          throw new Error(
            `Conversion verification failed in ${columns[i % columns.length]}`,
          )
      }
    })
    await sql`ANALYZE ${sql(relation)}`
  }

  return { migrate, checkDependencies }
}

// Importing this module supplies helpers; executing it runs the conversion.
if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  const databaseUrl = process.env.DATABASE_URL
  if (!databaseUrl) throw new Error('DATABASE_URL is required')
  const sql = postgres(databaseUrl, { prepare: false })
  try {
    const conversion = await createConversion(
      sql,
      process.env.MIGRATION_TABLE ?? 'customers',
    )
    await conversion.migrate()
  } finally {
    await sql.end()
  }
}
