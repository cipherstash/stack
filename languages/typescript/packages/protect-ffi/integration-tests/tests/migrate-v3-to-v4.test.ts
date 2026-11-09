import 'dotenv/config'
import {
  decryptBulk,
  type EncryptConfig,
  type EncryptedPayload,
  encryptBulk,
  encryptQuery,
  newClient,
} from '@cipherstash/protect-ffi'
import { Client } from 'pg'
import { afterAll, beforeAll, describe, expect, test } from 'vitest'
import {
  CHECK_VIOLATION,
  decryptV4,
  encryptV4,
  type Plaintext,
  queryV4,
  requireEqlV4,
  type V4Type,
} from './v4-codec'

// EQL v3 -> v4 migration, end to end, against live ZeroKMS and Postgres.
//
// v3 is what Stack 1.x writes: protect-ffi in `eqlVersion: 3` is the engine
// `@cipherstash/stack` encrypts through. v4 is what Stack Encrypt writes. The
// two use different ciphertext formats and derive their search terms
// differently, so a migration cannot be a cast or an edit of `v`: every value
// is decrypted with the v3 client and encrypted again as v4.
//
// The shape is the one a customer runs, in one table:
//
//   1. the v3 columns hold live data;
//   2. add a v4 column beside each one;
//   3. backfill: read the v3 payloads, decrypt them, encrypt the plaintexts as
//      v4, write them to the new columns;
//   4. switch queries to the v4 columns and v4 operands;
//   5. drop the v3 columns and rename the v4 ones into their place.
//
// The v4 values keep the v3 column's encryption context (`customers/email`,
// not `customers/email_v4`): the context is bound into the ciphertext and the
// search terms, so naming the logical column is what lets step 5 rename
// without re-encrypting again.
//
// Requires EQL v3 and v4 both installed (`mise run setup` installs v2, v3 and
// v4) and the v4 codec built (`mise run eql:v4:codec`); see ./v4-codec.ts.

const TABLE = 'customers'

const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    [TABLE]: {
      email: { cast_as: 'text', indexes: { unique: {} } },
      age: { cast_as: 'int', indexes: { ore: {} } },
      rank: { cast_as: 'int', indexes: { ope: {} } },
      bio: { cast_as: 'text', indexes: { match: {} } },
      active: { cast_as: 'boolean', indexes: {} },
    },
  },
}

type Customer = {
  email: string
  age: number
  rank: number
  bio: string
  active: boolean
}

const customers: Customer[] = [
  {
    email: 'ada@example.com',
    age: 36,
    rank: 3,
    bio: 'analytical engine notes',
    active: true,
  },
  {
    email: 'grace@example.com',
    age: 85,
    rank: 1,
    bio: 'compiler pioneer and admiral',
    active: true,
  },
  {
    email: 'alan@example.com',
    age: 41,
    rank: 2,
    bio: 'computable numbers and machines',
    active: false,
  },
  {
    email: 'edsger@example.com',
    age: 72,
    rank: 5,
    bio: 'structured programming advocate',
    active: false,
  },
  {
    email: 'barbara@example.com',
    age: 29,
    rank: 4,
    bio: 'abstraction and programming methodology',
    active: true,
  },
]

type Column = keyof Customer

/** Each column's v3 domain and the v4 type it migrates to, capability for capability. */
const columns: Record<Column, { v3: string; v4: V4Type; v4Domain: string }> = {
  email: {
    v3: 'public.eql_v3_text_eq',
    v4: 'TextEq',
    v4Domain: 'public.eql_v4_text_eq',
  },
  age: {
    v3: 'public.eql_v3_integer_ord_ore',
    v4: 'IntegerOrdOre',
    v4Domain: 'public.eql_v4_integer_ord_ore',
  },
  rank: {
    v3: 'public.eql_v3_integer_ord_ope',
    v4: 'IntegerOrdOpe',
    v4Domain: 'public.eql_v4_integer_ord_ope',
  },
  bio: {
    v3: 'public.eql_v3_text_match',
    v4: 'TextMatch',
    v4Domain: 'public.eql_v4_text_match',
  },
  active: {
    v3: 'public.eql_v3_boolean',
    v4: 'Boolean',
    v4Domain: 'public.eql_v4_boolean',
  },
}

const columnNames = Object.keys(columns) as Column[]

/** The emails of `rows` in id order: the oracle every query is compared to. */
const emails = (rows: Customer[]) => rows.map((row) => row.email)

/** Every plaintext of every customer, in the order the columns are decrypted. */
const everyPlaintext = customers.flatMap((customer) =>
  columnNames.map((column) => customer[column]),
)

/** A row that exists only inside the NULL test; no other test ever sees it. */
const NULL_ROW_ID = customers.length + 1

// 90s because one codec launch can block for 60s (`CODEC_TIMEOUT_MS`), and some
// tests launch it more than once. `spawnSync` blocks the event loop, so a test
// over its limit is reported as a timeout even when every assertion would pass.
describe('EQL v3 -> v4 migration', { timeout: 90_000 }, () => {
  const pg = new Client()
  let connected = false
  let v3Client: Awaited<ReturnType<typeof newClient>>

  /** Ids the query returns, read as emails through the plaintext oracle. */
  async function emailsWhere(sql: string, params: unknown[] = []) {
    const res = await pg.query<{ id: number }>(
      `SELECT id FROM ${TABLE} ${sql}`,
      params,
    )
    return res.rows.map((row) => customers[row.id - 1].email)
  }

  async function v3Operand(
    column: Column,
    plaintext: Plaintext,
    indexType: 'unique' | 'ore' | 'ope' | 'match',
  ) {
    return encryptQuery(v3Client, {
      plaintext,
      column,
      table: TABLE,
      indexType,
    })
  }

  function v4Operand(column: Column, value: Plaintext) {
    const [operand] = queryV4([
      { type: columns[column].v4, table: TABLE, column, value },
    ])
    return operand
  }

  /**
   * Step 3 for the rows `where` selects: read the v3 payloads, decrypt them with
   * the v3 client, encrypt the plaintexts as v4 and write them beside the v3
   * columns. A SQL NULL is no value, so it is neither decrypted nor encrypted
   * and its v4 column stays NULL: the `source IS NOT NULL` rule
   * `@cipherstash/migrate` applies to its own backfill.
   */
  async function backfill(where = '', params: unknown[] = []) {
    const res = await pg.query<
      Record<Column, EncryptedPayload | null> & { id: number }
    >(
      `SELECT id, ${columnNames.map((c) => `${c}::jsonb AS ${c}`).join(', ')}
       FROM ${TABLE} ${where} ORDER BY id`,
      params,
    )
    const cells = res.rows.flatMap((row) =>
      columnNames.flatMap((column) => {
        const ciphertext = row[column]
        return ciphertext === null ? [] : [{ id: row.id, column, ciphertext }]
      }),
    )
    if (cells.length === 0) return

    const plaintexts = await decryptBulk(v3Client, {
      ciphertexts: cells.map(({ ciphertext }) => ({ ciphertext })),
    })
    const v4 = encryptV4(
      cells.map(({ column }, i) => ({
        type: columns[column].v4,
        table: TABLE,
        column,
        value: plaintexts[i] as Plaintext,
      })),
    )
    for (const [i, { id, column }] of cells.entries()) {
      await pg.query(
        `UPDATE ${TABLE} SET ${column}_v4 = $1::jsonb WHERE id = $2`,
        [v4[i], id],
      )
    }
  }

  /** Every row's v4 columns, named `<column><suffix>`, opened in one codec launch. */
  async function decryptEveryV4Column(suffix: '' | '_v4') {
    const res = await pg.query<Record<string, unknown> & { id: number }>(
      `SELECT id, ${columnNames.map((c) => `${c}${suffix}::jsonb AS ${c}`).join(', ')}
       FROM ${TABLE} ORDER BY id`,
    )
    return decryptV4(
      res.rows.flatMap((row) =>
        columnNames.map((column) => ({
          type: columns[column].v4,
          table: TABLE,
          column,
          payload: row[column],
        })),
      ),
    )
  }

  beforeAll(async () => {
    v3Client = await newClient({ encryptConfig, eqlVersion: 3 })
    await pg.connect()
    connected = true
    await requireEqlV4(pg)

    // Step 1: the table as Stack 1.x left it — v3 columns only.
    await pg.query(`DROP TABLE IF EXISTS ${TABLE}`)
    await pg.query(`
      CREATE TABLE ${TABLE} (
        id integer PRIMARY KEY,
        ${columnNames.map((c) => `${c} ${columns[c].v3}`).join(',\n        ')}
      )
    `)

    const encrypted = await encryptBulk(v3Client, {
      plaintexts: customers.flatMap((customer) =>
        columnNames.map((column) => ({
          plaintext: customer[column],
          column,
          table: TABLE,
        })),
      ),
    })
    for (const index of customers.keys()) {
      const row = encrypted.slice(
        index * columnNames.length,
        (index + 1) * columnNames.length,
      )
      await pg.query(
        `INSERT INTO ${TABLE} (id, ${columnNames.join(', ')})
         VALUES ($1, ${columnNames.map((_, i) => `$${i + 2}::jsonb`).join(', ')})`,
        [index + 1, ...row],
      )
    }
    // Vitest's default hook timeout is 10s, too short for live ZeroKMS auth
    // and bulk encryption; a timeout here would skip every test in the file.
  }, 60_000)

  // In `afterAll`, not returned from `beforeAll`: a returned teardown runs only
  // when setup succeeds, so a throw after `connect()` would leave the socket
  // open and the table behind.
  afterAll(async () => {
    if (!connected) return
    try {
      await pg.query(`DROP TABLE IF EXISTS ${TABLE}`)
    } finally {
      await pg.end()
    }
  })

  test('the v3 table answers the queries the migration must preserve', async () => {
    const all = await pg.query<{ v: number }>(
      `SELECT DISTINCT (email::jsonb ->> 'v')::int AS v FROM ${TABLE}`,
    )
    expect(all.rows).toEqual([{ v: 3 }])

    expect(
      await emailsWhere('WHERE email = $1::jsonb::eql_v3.query_text_eq', [
        await v3Operand('email', 'alan@example.com', 'unique'),
      ]),
    ).toEqual(['alan@example.com'])

    expect(
      await emailsWhere(
        'WHERE age > $1::jsonb::eql_v3.query_integer_ord_ore ORDER BY id',
        [await v3Operand('age', 40, 'ore')],
      ),
    ).toEqual(emails(customers.filter((c) => c.age > 40)))

    expect(
      await emailsWhere(
        'WHERE bio @@ $1::jsonb::eql_v3.query_text_match ORDER BY id',
        [await v3Operand('bio', 'programming', 'match')],
      ),
    ).toEqual(emails(customers.filter((c) => c.bio.includes('programming'))))
  })

  test('a v3 payload cannot be cast into a v4 column', async () => {
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

  test('relabelling a v3 payload as v4 does not make it a v4 value', async () => {
    const res = await pg.query<{ email: EncryptedPayload }>(
      `SELECT email::jsonb AS email FROM ${TABLE} WHERE id = 3`,
    )
    const relabelled = {
      ...(res.rows[0].email as { hm: string }),
      v: 4,
    }

    // The codec opens a genuine v4 payload, so the refusal below is about the
    // payload and not a missing binary or bad credentials.
    const [genuine] = encryptV4([
      {
        type: 'TextEq',
        table: TABLE,
        column: 'email',
        value: 'alan@example.com',
      },
    ])
    expect(
      decryptV4([
        {
          type: 'TextEq',
          table: TABLE,
          column: 'email',
          payload: genuine,
        },
      ]),
    ).toEqual(['alan@example.com'])

    // Stack Encrypt refuses to open a cipherstash-client ciphertext.
    expect(() =>
      decryptV4([
        {
          type: 'TextEq',
          table: TABLE,
          column: 'email',
          payload: relabelled,
        },
      ]),
    ).toThrowError('unsupported EQL ciphertext producer or version')

    // And its search term was derived by the other producer, so a v4 query for
    // the same plaintext does not match it.
    const [v4Query] = queryV4([
      {
        type: 'TextEq',
        table: TABLE,
        column: 'email',
        value: 'alan@example.com',
      },
    ])
    // Both terms must exist, or `not.toEqual` passes on `undefined`.
    expect(typeof v4Query.hm).toBe('string')
    expect(typeof relabelled.hm).toBe('string')
    expect(v4Query.hm).not.toEqual(relabelled.hm)
  })

  test('backfill: decrypt every v3 value and re-encrypt it as v4 beside it', async () => {
    // Step 2: one v4 column per v3 column.
    for (const column of columnNames) {
      await pg.query(
        `ALTER TABLE ${TABLE} ADD COLUMN ${column}_v4 ${columns[column].v4Domain}`,
      )
    }

    // Step 3: read, decrypt with the v3 client, re-encrypt as v4, write back.
    await backfill()

    const versions = await pg.query<{ v: number; n: number }>(
      `SELECT (email_v4::jsonb ->> 'v')::int AS v, count(*)::int AS n FROM ${TABLE} GROUP BY 1`,
    )
    expect(versions.rows).toEqual([{ v: 4, n: customers.length }])
  })

  test('every migrated value decrypts as v4 to the original plaintext', async () => {
    expect(await decryptEveryV4Column('_v4')).toEqual(everyPlaintext)
  })

  test('equality: the v4 column finds the row the v3 column found', async () => {
    const v3 = await emailsWhere(
      'WHERE email = $1::jsonb::eql_v3.query_text_eq',
      [await v3Operand('email', 'alan@example.com', 'unique')],
    )
    const v4 = await emailsWhere(
      'WHERE email_v4 = $1::jsonb::eql_v4.query_text_eq',
      [v4Operand('email', 'alan@example.com')],
    )
    expect(v4).toEqual(v3)
    expect(v4).toEqual(['alan@example.com'])
  })

  test('range: ORE comparisons agree across versions', async () => {
    const expected = emails(customers.filter((c) => c.age > 40))
    const v3 = await emailsWhere(
      'WHERE age > $1::jsonb::eql_v3.query_integer_ord_ore ORDER BY id',
      [await v3Operand('age', 40, 'ore')],
    )
    const v4 = await emailsWhere(
      'WHERE age_v4 > $1::jsonb::eql_v4.query_integer_ord_ore ORDER BY id',
      [v4Operand('age', 40)],
    )
    expect(v3).toEqual(expected)
    expect(v4).toEqual(expected)
  })

  test('range: OPE comparisons agree across versions', async () => {
    const expected = emails(customers.filter((c) => c.rank > 2))
    const v3 = await emailsWhere(
      'WHERE rank > $1::jsonb::eql_v3.query_integer_ord_ope ORDER BY id',
      [await v3Operand('rank', 2, 'ope')],
    )
    const v4 = await emailsWhere(
      'WHERE rank_v4 > $1::jsonb::eql_v4.query_integer_ord_ope ORDER BY id',
      [v4Operand('rank', 2)],
    )
    expect(v3).toEqual(expected)
    expect(v4).toEqual(expected)
  })

  test('ordering: ORE and OPE sort orders agree across versions', async () => {
    const byAge = emails([...customers].sort((a, b) => a.age - b.age))
    expect(await emailsWhere('ORDER BY eql_v3.ord_term_ore(age)')).toEqual(
      byAge,
    )
    expect(await emailsWhere('ORDER BY eql_v4.ord_term_ore(age_v4)')).toEqual(
      byAge,
    )

    const byRank = emails([...customers].sort((a, b) => a.rank - b.rank))
    expect(await emailsWhere('ORDER BY eql_v3.ord_term(rank)')).toEqual(byRank)
    expect(await emailsWhere('ORDER BY eql_v4.ord_term(rank_v4)')).toEqual(
      byRank,
    )
  })

  test('match: the v4 bloom filter finds the rows the v3 one found', async () => {
    const expected = emails(
      customers.filter((c) => c.bio.includes('programming')),
    )
    const v3 = await emailsWhere(
      'WHERE bio @@ $1::jsonb::eql_v3.query_text_match ORDER BY id',
      [await v3Operand('bio', 'programming', 'match')],
    )
    const v4 = await emailsWhere(
      'WHERE bio_v4 @@ $1::jsonb::eql_v4.query_text_match ORDER BY id',
      [v4Operand('bio', 'programming')],
    )
    expect(v3).toEqual(expected)
    expect(v4).toEqual(expected)
  })

  test('a v3 operand against a v4 column matches nothing, silently', async () => {
    // The cut-over hazard: the column moved to v4 but the query still comes
    // from the v3 client. No operator is defined for the pair, so Postgres
    // falls back to `jsonb = jsonb` and returns no rows rather than erroring
    // (pinned in packages/eql/tests/sqlx/tests/v3_v4_coexistence_tests.rs).
    // Move the reads and the query client together.
    expect(
      await emailsWhere('WHERE email_v4 = $1::jsonb::eql_v3.query_text_eq', [
        await v3Operand('email', 'alan@example.com', 'unique'),
      ]),
    ).toEqual([])
  })

  test('a SQL NULL stays NULL through the backfill and is answered as NULL', async () => {
    // Before the cut-over, because the row needs both sets of columns. It is
    // removed in `finally` so the five-row oracles the other tests compare
    // against stay true whatever happens here. `active` is the one real value:
    // it is the last column, so the backfill has to pair it with the right v4
    // type and column after skipping the NULLs before it.
    await pg.query(
      `INSERT INTO ${TABLE} (id, active) SELECT $1::int, active FROM ${TABLE} WHERE id = 1`,
      [NULL_ROW_ID],
    )
    try {
      await backfill('WHERE id = $1', [NULL_ROW_ID])

      const migrated = await pg.query<Record<string, unknown>>(
        `SELECT ${columnNames.map((c) => `${c}_v4::jsonb AS ${c}`).join(', ')}
         FROM ${TABLE} WHERE id = $1`,
        [NULL_ROW_ID],
      )
      expect(migrated.rows).toEqual([
        {
          ...Object.fromEntries(columnNames.map((c) => [c, null])),
          active: expect.anything(),
        },
      ])
      expect(
        decryptV4(
          migrated.rows.map((row) => ({
            type: columns.active.v4,
            table: TABLE,
            column: 'active',
            payload: row.active,
          })),
        ),
      ).toEqual(customers.slice(0, 1).map((c) => c.active))

      // Ids, not `emailsWhere`: the NULL row has no entry in the plaintext oracle.
      const matched = await pg.query<{ id: number }>(
        `SELECT id FROM ${TABLE}
         WHERE email_v4 = $1::jsonb::eql_v4.query_text_eq`,
        [v4Operand('email', 'alan@example.com')],
      )
      expect(matched.rows).toEqual([{ id: 3 }])

      // The term functions are STRICT, so NULL sorts last rather than raising.
      for (const term of [
        'eql_v4.ord_term_ore(age_v4)',
        'eql_v4.ord_term(rank_v4)',
      ]) {
        const ordered = await pg.query<{ id: number }>(
          `SELECT id FROM ${TABLE} ORDER BY ${term}`,
        )
        expect(ordered.rows).toHaveLength(customers.length + 1)
        expect(ordered.rows.at(-1)).toEqual({ id: NULL_ROW_ID })
      }
    } finally {
      await pg.query(`DELETE FROM ${TABLE} WHERE id = $1`, [NULL_ROW_ID])
    }
  })

  test('cut-over: drop the v3 columns and the v4 values answer under the original names', async () => {
    // Step 5. The v4 values were encrypted under `customers/<column>`, so
    // renaming the database column changes nothing they are bound to.
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

    expect(await decryptEveryV4Column('')).toEqual(everyPlaintext)
  })
})
