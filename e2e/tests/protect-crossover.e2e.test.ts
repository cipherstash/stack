/**
 * Cross-store proof: one encrypted value moves between DynamoDB and Postgres
 * WITHOUT being re-encrypted, in either direction, and stays decryptable and
 * equality-queryable in both stores.
 *
 * An encrypted scalar is two strings in both stores:
 *
 *   DynamoDB (protect-dynamodb 6.x, Stack 1.x)   Postgres (EQL v3 column)
 *   ------------------------------------------   ------------------------
 *   <attr>__source                          <->  c   (the ciphertext)
 *   <attr>__hmac                            <->  hm  (the equality term)
 *
 * The rest of the Postgres envelope is `v: 3` and `i: { t, c }` (table and
 * column identity), which carries no secret and is rebuilt from the schema.
 * So moving a value is copying two strings; no key is used and nothing is
 * decrypted on the way. Every test here asserts the ciphertext arrives
 * byte-identical, then proves the receiving store can still decrypt it and
 * find it by equality.
 *
 * Origins covered:
 *  - items written by the REAL `@cipherstash/protect-dynamodb@6.0.1` (via
 *    `@cipherstash/protect@10.2.1`, protect-ffi 0.18.1), what the customer
 *    has today;
 *  - raw payloads from `@cipherstash/protect@10.2.1`'s `encrypt` (EQL v2);
 *  - rows and items written by the in-tree Stack 1.x.
 *
 * Needs the four `CS_*` credential variables and `DATABASE_URL` pointing at a
 * Postgres the suite may create tables in. EQL v3 is installed through the
 * real `stash eql install` (built by turbo's `^build`). Missing configuration
 * fails the file rather than skipping it: this proves a claim made to
 * customers. Runs from `vitest.protect-crossover.config.ts` as the
 * `test:protect-crossover` task.
 */
import { csColumn, csTable } from '@cipherstash/protect'
import { protectDynamoDB } from '@cipherstash/protect-dynamodb'
import { encryptedDynamoDB } from '@cipherstash/stack/dynamodb'
import { Encryption, encryptedTable, types } from '@cipherstash/stack/v3'
import { installEqlV3 } from '@cipherstash/test-kit/install'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { authConfigured, legacyProtect, ok } from './helpers/legacy-protect'

if (!authConfigured || !process.env.DATABASE_URL) {
  throw new Error(
    'protect-crossover: CS_WORKSPACE_CRN, CS_CLIENT_ID, CS_CLIENT_KEY, CS_CLIENT_ACCESS_KEY and DATABASE_URL must all be set (in the environment, e2e/.env or the repo-root .env)',
  )
}
const DATABASE_URL = process.env.DATABASE_URL

// ---------------------------------------------------------------------------
// Schemas. Same property keys and DB column names in every generation.
// ---------------------------------------------------------------------------

const legacyUsers = csTable('users', {
  email: csColumn('email').equality(),
  age: csColumn('age').dataType('number').equality(),
  notes: csColumn('notes'),
})

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  age: types.IntegerEq('age'),
  notes: types.Text('notes'),
})

const COLUMNS = ['email', 'age', 'notes'] as const
type Column = (typeof COLUMNS)[number]
type Model = { pk: string; email: string; age: number; notes: string }
type Item = Record<string, unknown>
type Envelope = {
  v: 3
  i: { t: string; c: string }
  c: string
  hm?: string
}

// ---------------------------------------------------------------------------
// The whole migration surface: two pure copies. No client, no key.
// ---------------------------------------------------------------------------

/** A DynamoDB attribute pair → the EQL v3 envelope a Postgres column stores. */
function toEnvelope(item: Item, column: Column): Envelope {
  const hm = item[`${column}__hmac`]
  return {
    v: 3,
    i: { t: users.tableName, c: column },
    c: item[`${column}__source`] as string,
    ...(typeof hm === 'string' ? { hm } : {}),
  }
}

/** An EQL envelope (v2 or v3) → the DynamoDB attribute pair. */
function toAttributes(
  payload: { c?: unknown; hm?: unknown },
  column: Column,
): Item {
  return {
    [`${column}__source`]: payload.c,
    ...(typeof payload.hm === 'string'
      ? { [`${column}__hmac`]: payload.hm }
      : {}),
  }
}

const itemToRow = (item: Item) =>
  Object.fromEntries(COLUMNS.map((col) => [col, toEnvelope(item, col)]))

const rowToItem = (
  pk: string,
  row: Record<Column, { c?: unknown; hm?: unknown }>,
): Item =>
  Object.assign({ pk }, ...COLUMNS.map((col) => toAttributes(row[col], col)))

/** The ciphertexts of an item or row, keyed by column, for byte comparison. */
const ciphertextsOfItem = (item: Item) =>
  Object.fromEntries(COLUMNS.map((col) => [col, item[`${col}__source`]]))
const ciphertextsOfRow = (row: Record<Column, { c?: unknown }>) =>
  Object.fromEntries(COLUMNS.map((col) => [col, row[col].c]))

const corpus: Model[] = [
  { pk: 'user#1', email: 'ada@example.com', age: 36, notes: 'engines' },
  { pk: 'user#2', email: 'grace@example.com', age: 85, notes: 'compilers' },
  { pk: 'user#3', email: 'alan@example.com', age: 36, notes: 'machines' },
]

describe('cross-store: DynamoDB <-> Postgres with no re-encryption', () => {
  const sql = postgres(DATABASE_URL, { prepare: false, onnotice: () => {} })
  const tableName = `crossover_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`

  let legacyClient: Awaited<ReturnType<typeof legacyProtect>>
  let legacy: ReturnType<typeof protectDynamoDB>
  let client: Awaited<ReturnType<typeof Encryption>>
  let stack: ReturnType<typeof encryptedDynamoDB>
  /** Items exactly as protect-dynamodb 6.0.1 PutItem'd them, by pk. */
  const legacyItems = new Map<string, Item>()

  /** Insert one row; payloads are bound as raw objects, never pre-stringified. */
  async function insert(pk: string, row: Record<string, unknown>) {
    await sql.unsafe(
      `INSERT INTO ${tableName} (pk, email, age, notes) VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb)`,
      [pk, row.email, row.age, row.notes] as never[],
    )
  }

  async function selectRow(pk: string): Promise<Record<Column, Envelope>> {
    const [row] = await sql.unsafe(
      `SELECT email::jsonb AS email, age::jsonb AS age, notes::jsonb AS notes FROM ${tableName} WHERE pk = $1`,
      [pk],
    )
    expect(row, `row ${pk}`).toBeDefined()
    return row as unknown as Record<Column, Envelope>
  }

  /** The pks an SQL equality query finds, using a term Stack 1.x mints. */
  async function findBy(
    column: 'email' | 'age',
    value: string | number,
  ): Promise<string[]> {
    const term = ok(
      await client.encryptQuery(
        value as never,
        { table: users, column: users[column] } as never,
      ),
      `encryptQuery ${column}`,
    )
    const domain = column === 'email' ? 'query_text_eq' : 'query_integer_eq'
    const rows = await sql.unsafe(
      `SELECT pk FROM ${tableName} WHERE eql_v3.eq("${column}", $1::jsonb::eql_v3.${domain})`,
      [term as never],
    )
    // Sorted here, not by ORDER BY: the database collation decides where '#'
    // and digits fall, and the expectations are in JavaScript's order.
    return rows.map((r) => (r as unknown as { pk: string }).pk).sort()
  }

  beforeAll(async () => {
    await installEqlV3(DATABASE_URL, 'postgres')
    await sql.unsafe(`
      CREATE TABLE ${tableName} (
        pk    text PRIMARY KEY,
        email public.eql_v3_text_eq,
        age   public.eql_v3_integer_eq,
        notes public.eql_v3_text
      )`)

    legacyClient = await legacyProtect([legacyUsers])
    legacy = protectDynamoDB({ protectClient: legacyClient })
    client = await Encryption({ schemas: [users] })
    stack = encryptedDynamoDB({ encryptionClient: client })

    const written = ok(
      await legacy.bulkEncryptModels(corpus, legacyUsers),
      'protect-dynamodb bulkEncryptModels',
    ) as Item[]
    for (const item of written) legacyItems.set(item.pk as string, item)
  }, 180_000)

  afterAll(async () => {
    await sql.unsafe(`DROP TABLE IF EXISTS ${tableName}`)
    await sql.end()
  })

  // -------------------------------------------------------------------------
  // DynamoDB → Postgres
  // -------------------------------------------------------------------------

  describe('protect-dynamodb 6.0.1 items → Postgres EQL v3 columns', () => {
    beforeAll(async () => {
      for (const item of legacyItems.values()) {
        await insert(item.pk as string, itemToRow(item))
      }
    })

    it('the EQL v3 column domains accept the copied attributes', async () => {
      const [{ count }] = await sql.unsafe(
        `SELECT count(*)::int AS count FROM ${tableName}`,
      )
      expect(count).toBe(corpus.length)
    })

    it('stores the DynamoDB ciphertext and HMAC byte-for-byte', async () => {
      for (const item of legacyItems.values()) {
        const row = await selectRow(item.pk as string)
        expect(ciphertextsOfRow(row), item.pk as string).toEqual(
          ciphertextsOfItem(item),
        )
        expect(row.email.hm).toBe(item.email__hmac)
        expect(row.age.hm).toBe(item.age__hmac)
      }
    })

    it('Stack 1.x decrypts the Postgres rows', async () => {
      for (const model of corpus) {
        const row = await selectRow(model.pk)
        const decrypted = ok(
          await client.decryptModel({ pk: model.pk, ...row } as never),
          `decryptModel ${model.pk}`,
        )
        expect(decrypted).toEqual(model)
      }
    })

    it('SQL equality queries find exactly the right rows', async () => {
      for (const model of corpus) {
        expect(await findBy('email', model.email)).toEqual([model.pk])
        expect(await findBy('age', model.age)).toEqual(
          corpus
            .filter((m) => m.age === model.age)
            .map((m) => m.pk)
            .sort(),
        )
      }
      expect(await findBy('email', 'nobody@example.com')).toEqual([])
    })

    it('round trip DynamoDB → Postgres → DynamoDB returns the original item exactly', async () => {
      for (const item of legacyItems.values()) {
        const back = rowToItem(
          item.pk as string,
          await selectRow(item.pk as string),
        )
        expect(back).toEqual(item)
      }
    })
  })

  // -------------------------------------------------------------------------
  // Postgres → DynamoDB
  // -------------------------------------------------------------------------

  describe('Stack 1.x Postgres rows → DynamoDB items', () => {
    const model: Model = {
      pk: 'user#10',
      email: 'barbara@example.com',
      age: 36,
      notes: 'abstraction',
    }
    let row: Record<Column, Envelope>
    let item: Item

    beforeAll(async () => {
      const encrypted = ok(
        await client.encryptModel(model, users),
        'encryptModel (Postgres row)',
      ) as Record<string, unknown>
      await insert(model.pk, encrypted)
      row = await selectRow(model.pk)
      item = rowToItem(model.pk, row)
    })

    it('copies the ciphertext and HMAC byte-for-byte', () => {
      expect(ciphertextsOfItem(item)).toEqual(ciphertextsOfRow(row))
      expect(item.email__hmac).toBe(row.email.hm)
      expect(item.age__hmac).toBe(row.age.hm)
      expect(item).not.toHaveProperty('notes__hmac')
    })

    it('Stack 1.x encryptedDynamoDB decrypts the item', async () => {
      expect(
        ok(await stack.decryptModel(item, users), 'stack decryptModel'),
      ).toEqual(model)
    })

    it('protect-dynamodb 6.0.1 decrypts the item too', async () => {
      expect(
        ok(
          await legacy.decryptModel(item, legacyUsers),
          'protect-dynamodb decryptModel',
        ),
      ).toEqual(model)
    })

    it('the item carries the same __hmac a native DynamoDB write would, so existing key conditions match it', async () => {
      const native = ok(
        await stack.encryptModel(model, users),
        'stack encryptModel (DynamoDB)',
      ) as Item
      expect(item.email__hmac).toBe(native.email__hmac)
      expect(item.age__hmac).toBe(native.age__hmac)
      const [legacyTerm] = ok(
        await legacy.createSearchTerms([
          { value: model.email, column: legacyUsers.email, table: legacyUsers },
        ]),
        'protect-dynamodb createSearchTerms',
      )
      expect(item.email__hmac).toBe(legacyTerm)
    })

    it('one SQL query finds the Stack row beside the protect-dynamodb rows', async () => {
      expect(await findBy('age', 36)).toEqual(
        ['user#1', 'user#10', 'user#3'].sort(),
      )
    })
  })

  // -------------------------------------------------------------------------
  // Raw protect 10.2.1 payloads (EQL v2) → both stores
  // -------------------------------------------------------------------------

  describe('raw @cipherstash/protect 10.2.1 payloads → both stores', () => {
    const model: Model = {
      pk: 'user#20',
      email: 'edsger@example.com',
      age: 72,
      notes: 'goto considered harmful',
    }
    let payloads: Record<Column, { c: string; hm?: string; v: number }>

    beforeAll(async () => {
      const entries = await Promise.all(
        COLUMNS.map(async (col) => [
          col,
          ok(
            await legacyClient.encrypt(model[col] as never, {
              table: legacyUsers,
              column: legacyUsers[col],
            }),
            `protect encrypt ${col}`,
          ),
        ]),
      )
      payloads = Object.fromEntries(entries)
      expect(payloads.email.v).toBe(2)
    })

    it('becomes a DynamoDB item Stack 1.x decrypts, identical to what protect-dynamodb wrote', async () => {
      const item = rowToItem(model.pk, payloads)
      expect(
        ok(await stack.decryptModel(item, users), 'stack decryptModel'),
      ).toEqual(model)
      // protect-dynamodb's write path is exactly this copy.
      expect(item.email__hmac).toBe(
        ok(
          await legacy.createSearchTerms([
            {
              value: model.email,
              column: legacyUsers.email,
              table: legacyUsers,
            },
          ]),
          'createSearchTerms',
        )[0],
      )
    })

    it('becomes a Postgres EQL v3 row that SQL finds and Stack 1.x decrypts', async () => {
      // The same two copies as every other test: payload → attributes →
      // EQL v3 envelope.
      await insert(model.pk, itemToRow(rowToItem(model.pk, payloads)))
      const stored = await selectRow(model.pk)
      expect(ciphertextsOfRow(stored)).toEqual(ciphertextsOfRow(payloads))

      expect(await findBy('email', model.email)).toEqual([model.pk])
      expect(
        ok(
          await client.decryptModel({ pk: model.pk, ...stored } as never),
          'decryptModel',
        ),
      ).toEqual(model)
    })
  })
})
