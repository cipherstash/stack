import 'dotenv/config'
import {
  decryptBulk,
  type EncryptConfig,
  type EncryptedPayload,
  newClient,
} from '@cipherstash/protect-ffi'
import { Client } from 'pg'
import { beforeAll, describe, expect, test } from 'vitest'
import {
  CHECK_VIOLATION,
  decryptV4,
  encryptV4,
  type Plaintext,
  queryV4,
  requireEqlV4,
  type V4Type,
} from './v4-codec'

// EQL v2 -> v4 migration, end to end, against live ZeroKMS and Postgres.
//
// The v2 data is written by the real Protect.js, `@cipherstash/protect@10.2.1`
// (protect-ffi 0.18.1, cipherstash-client 0.28), the last client customers
// used before Stack. Not by today's protect-ffi in v2 mode: whether old
// ciphertext still reads is the question, so the old client writes it.
//
// v2 stores every column as one type, `eql_v2_encrypted`, and decides what a
// column can answer from the payload's index terms. v4 has a domain per
// capability, so the migration picks one per column. The payloads are also
// produced differently (cipherstash-client vs Stack Encrypt), so as with v3
// every value is decrypted and encrypted again; nothing converts in place.
//
// The steps are the ones migrate-v3-to-v4.test.ts runs, in one table: add a
// v4 column beside each v2 column, backfill by decrypting with the client
// Stack 1.x encrypts through (in-tree protect-ffi, which still reads v2) and
// re-encrypting as v4, check every query answers the same rows, then drop the
// v2 columns and rename the v4 ones into their place.
//
// Requires EQL v2 and v4 both installed (`mise run setup` installs v2, v3 and
// v4) and the v4 codec built (`mise run eql:v4:codec`); see ./v4-codec.ts.

const TABLE = 'accounts'

// Stack 1.x's engine needs a config for the table to decrypt it.
const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    [TABLE]: {
      email: { cast_as: 'text', indexes: { unique: {} } },
      age: { cast_as: 'number', indexes: { ore: {} } },
      bio: { cast_as: 'text', indexes: { match: {} } },
      active: { cast_as: 'boolean', indexes: {} },
    },
  },
}

/**
 * Build Protect's native client and the customer's Protect.js schema for the
 * same workspace.
 *
 * Through `import()`: Protect 10.2.1's `types` export condition names its
 * ESM declarations, so TypeScript refuses a static import from this CommonJS
 * suite even though the package ships a `require` build.
 *
 * cipherstash-client 0.28 does not derive its service hosts from the
 * workspace CRN, so point `CS_CTS_HOST` / `CS_ZEROKMS_HOST` at the CRN's
 * region while the client is built, then restore them: protect-ffi must keep
 * deriving its own. The same workaround as e2e/tests/protect-dynamodb-compat.
 */
async function legacyProtect() {
  const { csColumn, csTable, protect } = await import('@cipherstash/protect')
  const table = csTable(TABLE, {
    email: csColumn('email').equality(),
    age: csColumn('age').dataType('number').orderAndRange(),
    bio: csColumn('bio').freeTextSearch(),
    active: csColumn('active').dataType('boolean'),
  })
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
    const client = await protect({
      schemas: [table],
      workspaceCrn: crn,
      clientId: process.env.CS_CLIENT_ID,
      clientKey: process.env.CS_CLIENT_KEY,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY,
    })
    return { client, table }
  } finally {
    for (const [key, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[key]
      else process.env[key] = value
    }
  }
}

/** Unwrap Protect's `{ data } | { failure }`, failing the test on `failure`. */
function ok<T>(
  result: { data: T; failure?: undefined } | { failure: unknown },
  label: string,
): T {
  if ('failure' in result && result.failure !== undefined) {
    const failure = result.failure as { message?: unknown }
    throw new Error(
      `${label} failed: ${String(failure?.message ?? '')} ${JSON.stringify(failure)}`,
    )
  }
  return (result as { data: T }).data
}

/**
 * Protect 10.2.1's plaintext type (protect-ffi 0.18.1's `JsPlaintext`) leaves
 * out `boolean`, though it encrypts one; e2e/tests/protect-dynamodb-compat
 * pins that it does.
 */
const asLegacy = (value: Plaintext) => value as string | number

type Account = {
  email: string
  age: number
  bio: string
  active: boolean
}

const accounts: Account[] = [
  {
    email: 'ada@example.com',
    age: 36,
    bio: 'analytical engine notes',
    active: true,
  },
  {
    email: 'grace@example.com',
    age: 85,
    bio: 'compiler pioneer and admiral',
    active: true,
  },
  {
    email: 'alan@example.com',
    age: 41,
    bio: 'computable numbers and machines',
    active: false,
  },
  {
    email: 'edsger@example.com',
    age: 72,
    bio: 'structured programming advocate',
    active: false,
  },
  {
    email: 'barbara@example.com',
    age: 29,
    bio: 'abstraction and programming methodology',
    active: true,
  },
]

type Column = keyof Account

/**
 * The v4 type each v2 column migrates to. Protect's `dataType('number')`
 * encrypted a float64, so `age` keeps that and becomes `DoubleOrdOre`, not an
 * integer type.
 */
const columns: Record<Column, { v4: V4Type; v4Domain: string }> = {
  email: { v4: 'TextEq', v4Domain: 'public.eql_v4_text_eq' },
  age: { v4: 'DoubleOrdOre', v4Domain: 'public.eql_v4_double_ord_ore' },
  bio: { v4: 'TextMatch', v4Domain: 'public.eql_v4_text_match' },
  active: { v4: 'Boolean', v4Domain: 'public.eql_v4_boolean' },
}

const columnNames = Object.keys(columns) as Column[]

const emails = (rows: Account[]) => rows.map((row) => row.email)

describe('EQL v2 -> v4 migration', () => {
  const pg = new Client()
  let legacy: Awaited<ReturnType<typeof legacyProtect>>
  let stackClient: Awaited<ReturnType<typeof newClient>>

  async function emailsWhere(sql: string, params: unknown[] = []) {
    const res = await pg.query<{ id: number }>(
      `SELECT id FROM ${TABLE} ${sql}`,
      params,
    )
    return res.rows.map((row) => accounts[row.id - 1].email)
  }

  /** A v2 search term from Protect 10.2.1, as its customers queried. */
  async function v2Term(column: Column, value: Plaintext) {
    const [term] = ok(
      await legacy.client.createSearchTerms([
        {
          value: asLegacy(value),
          column: legacy.table[column],
          table: legacy.table,
        },
      ]),
      'createSearchTerms',
    )
    return term
  }

  function v4Operand(column: Column, value: Plaintext) {
    const [operand] = queryV4([
      { type: columns[column].v4, table: TABLE, column, value },
    ])
    return operand
  }

  beforeAll(async () => {
    legacy = await legacyProtect()
    stackClient = await newClient({ encryptConfig })
    await pg.connect()
    await requireEqlV4(pg)

    // The table as Protect.js left it: every column `eql_v2_encrypted`.
    await pg.query(`DROP TABLE IF EXISTS ${TABLE}`)
    await pg.query(`
      CREATE TABLE ${TABLE} (
        id integer PRIMARY KEY,
        ${columnNames.map((c) => `${c} eql_v2_encrypted`).join(',\n        ')}
      )
    `)
    for (const column of columnNames) {
      await pg.query('SELECT eql_v2.add_encrypted_constraint($1, $2)', [
        TABLE,
        column,
      ])
    }

    const byColumn = new Map<Column, unknown[]>()
    for (const column of columnNames) {
      const encrypted = ok(
        await legacy.client.bulkEncrypt(
          accounts.map((account) => ({ plaintext: asLegacy(account[column]) })),
          { column: legacy.table[column], table: legacy.table },
        ),
        `bulkEncrypt ${column}`,
      )
      byColumn.set(
        column,
        encrypted.map((item) => item.data),
      )
    }
    for (const index of accounts.keys()) {
      await pg.query(
        `INSERT INTO ${TABLE} (id, ${columnNames.join(', ')})
         VALUES ($1, ${columnNames.map((_, i) => `$${i + 2}::jsonb`).join(', ')})`,
        [index + 1, ...columnNames.map((c) => byColumn.get(c)?.[index])],
      )
    }

    return async () => {
      await pg.query(`DROP TABLE IF EXISTS ${TABLE}`)
      await pg.end()
    }
  })

  test('the v2 table answers the queries the migration must preserve', async () => {
    const versions = await pg.query<{ v: number }>(
      `SELECT DISTINCT (email::jsonb ->> 'v')::int AS v FROM ${TABLE}`,
    )
    expect(versions.rows).toEqual([{ v: 2 }])

    expect(
      await emailsWhere('WHERE email = $1::jsonb', [
        await v2Term('email', 'alan@example.com'),
      ]),
    ).toEqual(['alan@example.com'])

    expect(
      await emailsWhere('WHERE age > $1::jsonb ORDER BY id', [
        await v2Term('age', 40),
      ]),
    ).toEqual(emails(accounts.filter((a) => a.age > 40)))

    expect(await emailsWhere('ORDER BY eql_v2.order_by(age)')).toEqual(
      emails([...accounts].sort((a, b) => a.age - b.age)),
    )

    expect(
      await emailsWhere('WHERE bio LIKE $1::jsonb ORDER BY id', [
        await v2Term('bio', 'programming'),
      ]),
    ).toEqual(emails(accounts.filter((a) => a.bio.includes('programming'))))
  })

  test('a v2 payload cannot be cast into a v4 column', async () => {
    await pg.query(
      `ALTER TABLE ${TABLE} ADD COLUMN probe ${columns.email.v4Domain}`,
    )
    try {
      await expect(
        pg.query(
          `UPDATE ${TABLE} SET probe = email::jsonb::${columns.email.v4Domain}`,
        ),
      ).rejects.toMatchObject({ code: CHECK_VIOLATION })
    } finally {
      await pg.query(`ALTER TABLE ${TABLE} DROP COLUMN probe`)
    }
  })

  test('relabelling a v2 payload as v4 does not make it a v4 value', async () => {
    const res = await pg.query<{ email: Record<string, unknown> }>(
      `SELECT email::jsonb AS email FROM ${TABLE} WHERE id = 3`,
    )
    expect(() =>
      decryptV4([
        {
          type: 'TextEq',
          table: TABLE,
          column: 'email',
          payload: { ...res.rows[0].email, v: 4 },
        },
      ]),
    ).toThrowError()
  })

  test('backfill: decrypt every v2 value and re-encrypt it as v4 beside it', async () => {
    for (const column of columnNames) {
      await pg.query(
        `ALTER TABLE ${TABLE} ADD COLUMN ${column}_v4 ${columns[column].v4Domain}`,
      )
    }

    const res = await pg.query<
      Record<Column, EncryptedPayload> & { id: number }
    >(
      `SELECT id, ${columnNames.map((c) => `${c}::jsonb AS ${c}`).join(', ')}
       FROM ${TABLE} ORDER BY id`,
    )
    // Stack 1.x's engine reads the payloads Protect 10.2.1 wrote.
    const plaintexts = await decryptBulk(stackClient, {
      ciphertexts: res.rows.flatMap((row) =>
        columnNames.map((column) => ({ ciphertext: row[column] })),
      ),
    })
    expect(plaintexts).toEqual(
      accounts.flatMap((account) => columnNames.map((c) => account[c])),
    )

    const v4 = encryptV4(
      res.rows.flatMap((_, r) =>
        columnNames.map((column, c) => ({
          type: columns[column].v4,
          table: TABLE,
          column,
          value: plaintexts[r * columnNames.length + c] as Plaintext,
        })),
      ),
    )
    for (const [r, row] of res.rows.entries()) {
      const values = v4.slice(
        r * columnNames.length,
        (r + 1) * columnNames.length,
      )
      await pg.query(
        `UPDATE ${TABLE} SET ${columnNames
          .map((c, i) => `${c}_v4 = $${i + 2}::jsonb`)
          .join(', ')} WHERE id = $1`,
        [row.id, ...values],
      )
    }

    const versions = await pg.query<{ v: number; n: number }>(
      `SELECT (email_v4::jsonb ->> 'v')::int AS v, count(*)::int AS n FROM ${TABLE} GROUP BY 1`,
    )
    expect(versions.rows).toEqual([{ v: 4, n: accounts.length }])
  })

  test('every migrated value decrypts as v4 to the original plaintext', async () => {
    const res = await pg.query<Record<string, unknown> & { id: number }>(
      `SELECT id, ${columnNames.map((c) => `${c}_v4::jsonb AS ${c}`).join(', ')}
       FROM ${TABLE} ORDER BY id`,
    )
    expect(
      decryptV4(
        res.rows.flatMap((row) =>
          columnNames.map((column) => ({
            type: columns[column].v4,
            table: TABLE,
            column,
            payload: row[column],
          })),
        ),
      ),
    ).toEqual(accounts.flatMap((account) => columnNames.map((c) => account[c])))
  })

  test('equality: the v4 column finds the row the v2 column found', async () => {
    const v2 = await emailsWhere('WHERE email = $1::jsonb', [
      await v2Term('email', 'alan@example.com'),
    ])
    const v4 = await emailsWhere(
      'WHERE email_v4 = $1::jsonb::eql_v4.query_text_eq',
      [v4Operand('email', 'alan@example.com')],
    )
    expect(v4).toEqual(v2)
    expect(v4).toEqual(['alan@example.com'])
  })

  test('range and ordering: ORE agrees across versions', async () => {
    const older = emails(accounts.filter((a) => a.age > 40))
    expect(
      await emailsWhere('WHERE age > $1::jsonb ORDER BY id', [
        await v2Term('age', 40),
      ]),
    ).toEqual(older)
    expect(
      await emailsWhere(
        'WHERE age_v4 > $1::jsonb::eql_v4.query_double_ord_ore ORDER BY id',
        [v4Operand('age', 40)],
      ),
    ).toEqual(older)

    const byAge = emails([...accounts].sort((a, b) => a.age - b.age))
    expect(await emailsWhere('ORDER BY eql_v2.order_by(age)')).toEqual(byAge)
    expect(await emailsWhere('ORDER BY eql_v4.ord_term_ore(age_v4)')).toEqual(
      byAge,
    )
  })

  test('match: the v4 bloom filter finds the rows the v2 one found', async () => {
    const expected = emails(
      accounts.filter((a) => a.bio.includes('programming')),
    )
    expect(
      await emailsWhere('WHERE bio LIKE $1::jsonb ORDER BY id', [
        await v2Term('bio', 'programming'),
      ]),
    ).toEqual(expected)
    expect(
      await emailsWhere(
        'WHERE bio_v4 @@ $1::jsonb::eql_v4.query_text_match ORDER BY id',
        [v4Operand('bio', 'programming')],
      ),
    ).toEqual(expected)
  })

  test('cut-over: drop the v2 columns and the v4 values answer under the original names', async () => {
    for (const column of columnNames) {
      await pg.query(`ALTER TABLE ${TABLE} DROP COLUMN ${column}`)
      await pg.query(
        `ALTER TABLE ${TABLE} RENAME COLUMN ${column}_v4 TO ${column}`,
      )
    }

    expect(
      await emailsWhere('WHERE email = $1::jsonb::eql_v4.query_text_eq', [
        v4Operand('email', 'grace@example.com'),
      ]),
    ).toEqual(['grace@example.com'])

    const res = await pg.query<{ active: unknown }>(
      `SELECT active::jsonb AS active FROM ${TABLE} ORDER BY id`,
    )
    expect(
      decryptV4(
        res.rows.map((row) => ({
          type: 'Boolean' as const,
          table: TABLE,
          column: 'active',
          payload: row.active,
        })),
      ),
    ).toEqual(accounts.map((a) => a.active))
  })
})
