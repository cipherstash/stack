import 'dotenv/config'
import {
  type EncryptConfig,
  type EncryptedPayload,
  type IntegerOrdOpe,
  type IntegerOrdOpeQuery,
  type IntegerOrdOre,
  type IntegerOrdOreQuery,
  type TextEq,
  type TextEqQuery,
  type TextSearchOreQuery,
  decrypt,
  decryptBulk,
  encrypt,
  encryptBulk,
  encryptQuery,
  newClient,
} from '@cipherstash/protect-ffi'
import { Client, type QueryResult } from 'pg'
import { beforeAll, beforeEach, describe, expect, test } from 'vitest'
import { v3WireKeys } from './common'

// Requires the eql_v3 schema: `mise run eql:v3:install` (part of `mise
// setup`) installs the SQL bundled with the exact @cipherstash/eql version
// locked by the integration-test package.
//
// The config -> eql_v3 domain mapping is asserted, not assumed: each
// payload's exact key set is checked against the vendored domain type
// before INSERT (below), and the live domain CHECK on the public.eql_v3_text_eq
// / public.eql_v3_integer_ord_ore / public.eql_v3_integer_ord_ope columns validates the
// required keys on INSERT.
const encryptConfig: EncryptConfig = {
  v: 1,
  tables: {
    v3pg: {
      email: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
      score: {
        cast_as: 'int',
        indexes: { ore: {} },
      },
      rank: {
        cast_as: 'int',
        indexes: { ope: {} },
      },
      bio: {
        cast_as: 'text',
        indexes: { unique: {}, ore: {}, match: {} },
      },
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'v3pg/profile' } },
      },
    },
  },
}

const v2EmailOnlyConfig: EncryptConfig = {
  v: 1,
  tables: {
    v3pg: {
      email: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
    },
  },
}

// Exact wire key sets, compile-time-checked against the vendored eql_v3
// domain types (see v3WireKeys).
const textEqKeys = v3WireKeys<TextEq>()('v', 'i', 'c', 'hm')
const integerOrdOreKeys = v3WireKeys<IntegerOrdOre>()('v', 'i', 'c', 'ob')
const integerOrdOpeKeys = v3WireKeys<IntegerOrdOpe>()('v', 'i', 'c', 'op')

// Query operands are the term-only twins: no `c`.
const textEqQueryKeys = v3WireKeys<TextEqQuery>()('v', 'i', 'hm')
// `bio` is unique + ore + match, so it lands on the ORE search domain: the
// bare text_search carries the OPE `op` term instead of `ob`.
const textSearchOreQueryKeys = v3WireKeys<TextSearchOreQuery>()(
  'v',
  'i',
  'hm',
  'ob',
  'bf',
)
const integerOrdOreQueryKeys = v3WireKeys<IntegerOrdOreQuery>()('v', 'i', 'ob')
const integerOrdOpeQueryKeys = v3WireKeys<IntegerOrdOpeQuery>()('v', 'i', 'op')

describe('postgres eql_v3', () => {
  // Vitest does not await the `describe` callback, so an `async describe` with
  // top-level `await`s can finish collection before they resolve — leaving the
  // hooks and tests below unregistered. Client + connection setup therefore
  // lives in `beforeAll` (an async lifecycle hook), with teardown returned
  // from it (Vitest runs the returned fn as `afterAll`).
  const pg = new Client()
  let protectClient: Awaited<ReturnType<typeof newClient>>

  beforeAll(async () => {
    protectClient = await newClient({ encryptConfig, eqlVersion: 3 })
    await pg.connect()

    await pg.query('DROP TABLE IF EXISTS encrypted_v3')

    await pg.query(`
      CREATE TABLE encrypted_v3 (
        id SERIAL PRIMARY KEY,
        email public.eql_v3_text_eq,
        score public.eql_v3_integer_ord_ore,
        rank public.eql_v3_integer_ord_ope,
        bio public.eql_v3_text_search_ore,
        profile public.eql_v3_json_search
      )
    `)

    return async () => {
      await pg.query('DROP TABLE encrypted_v3')
      await pg.end()
    }
  })

  beforeEach(async () => {
    await pg.query('BEGIN')
    return async () => {
      await pg.query('ROLLBACK')
    }
  })

  test('the domain CHECK accepts protect-ffi v3 output', async () => {
    const email = await encrypt(protectClient, {
      plaintext: 'check@example.com',
      column: 'email',
      table: 'v3pg',
    })
    const score = await encrypt(protectClient, {
      plaintext: 10,
      column: 'score',
      table: 'v3pg',
    })

    // The INSERT below proves the domain CHECKs accept the payloads (the
    // required keys are present); these exact-set assertions additionally
    // prove nothing extra was provisioned — a CHECK does not reject a
    // payload that selected a richer domain than the config asked for.
    expect(Object.keys(email).sort()).toEqual(textEqKeys)
    expect(Object.keys(score).sort()).toEqual(integerOrdOreKeys)

    await pg.query(
      'INSERT INTO encrypted_v3 (email, score) VALUES ($1::jsonb, $2::jsonb)',
      [email, score],
    )

    const res: QueryResult<{
      email: EncryptedPayload
      score: EncryptedPayload
    }> = await pg.query('SELECT email::jsonb, score::jsonb FROM encrypted_v3')

    expect(res.rowCount).toBe(1)
    expect(
      await decrypt(protectClient, { ciphertext: res.rows[0].email }),
    ).toBe('check@example.com')
    expect(
      await decrypt(protectClient, { ciphertext: res.rows[0].score }),
    ).toBe(10)
  })

  test('the domain CHECK rejects a v2 payload', async () => {
    const v2Client = await newClient({
      encryptConfig: v2EmailOnlyConfig,
      eqlVersion: 2,
    })
    const v2Email = await encrypt(v2Client, {
      plaintext: 'v2@example.com',
      column: 'email',
      table: 'v3pg',
    })

    await expect(
      pg.query('INSERT INTO encrypted_v3 (email) VALUES ($1::jsonb)', [
        v2Email,
      ]),
    ).rejects.toThrowError()
    // The failed INSERT aborts the wrapping transaction; reset it so the
    // beforeEach ROLLBACK still succeeds.
    await pg.query('ROLLBACK')
    await pg.query('BEGIN')
  })

  test('ORDER BY the ord_term_ore extractor sorts by plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 30, column: 'score', table: 'v3pg' },
        { plaintext: 10, column: 'score', table: 'v3pg' },
        { plaintext: 20, column: 'score', table: 'v3pg' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expect(Object.keys(ciphertext).sort()).toEqual(integerOrdOreKeys)
    }

    await pg.query(
      'INSERT INTO encrypted_v3 (score) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ score: EncryptedPayload }> = await pg.query(`
      SELECT score::jsonb FROM encrypted_v3
      ORDER BY eql_v3.ord_term_ore(score) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.score })),
    })
    expect(decrypted).toEqual([10, 20, 30])
  })

  // Real-ciphertext _ord_ope coverage: cipherstash-client 0.38.1
  // emits the scalar `op` (CLLW-OPE) term, so an `ope`-indexed column can be
  // produced end-to-end (0.38.0 dropped the term at encrypt time). The OPE
  // extractor is the unsuffixed `ord_term`; ORE carries the `_ore` suffix.
  test('ORDER BY the ord_term extractor sorts an ope column by plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 30, column: 'rank', table: 'v3pg' },
        { plaintext: 10, column: 'rank', table: 'v3pg' },
        { plaintext: 20, column: 'rank', table: 'v3pg' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expect(Object.keys(ciphertext).sort()).toEqual(integerOrdOpeKeys)
    }

    await pg.query(
      'INSERT INTO encrypted_v3 (rank) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const res: QueryResult<{ rank: EncryptedPayload }> = await pg.query(`
      SELECT rank::jsonb FROM encrypted_v3
      ORDER BY eql_v3.ord_term(rank) ASC
    `)

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.rank })),
    })
    expect(decrypted).toEqual([10, 20, 30])
  })

  // ---------------------------------------------------------------------
  // encryptQuery round-trips: rows written via encrypt(), then
  // matched with term-only operands via the public SQL entry points
  // (`col <op> $1::jsonb::eql_v3.query_<name>`).
  // ---------------------------------------------------------------------

  test('equality: a query_text_eq operand finds the matching row', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 'a@example.com', column: 'email', table: 'v3pg' },
        { plaintext: 'b@example.com', column: 'email', table: 'v3pg' },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted_v3 (email) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const operand = await encryptQuery(protectClient, {
      plaintext: 'b@example.com',
      column: 'email',
      table: 'v3pg',
      indexType: 'unique',
    })
    expect(Object.keys(operand as object).sort()).toEqual(textEqQueryKeys)

    const res: QueryResult<{ email: EncryptedPayload }> = await pg.query(
      `
      SELECT email::jsonb FROM encrypted_v3
      WHERE email = $1::jsonb::eql_v3.query_text_eq
      `,
      [operand],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.email })),
    })
    expect(decrypted).toEqual(['b@example.com'])
  })

  test('range: a query_integer_ord_ore operand matches plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 10, column: 'score', table: 'v3pg' },
        { plaintext: 20, column: 'score', table: 'v3pg' },
        { plaintext: 30, column: 'score', table: 'v3pg' },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted_v3 (score) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const operand = await encryptQuery(protectClient, {
      plaintext: 15,
      column: 'score',
      table: 'v3pg',
      indexType: 'ore',
    })
    expect(Object.keys(operand as object).sort()).toEqual(
      integerOrdOreQueryKeys,
    )

    const res: QueryResult<{ score: EncryptedPayload }> = await pg.query(
      `
      SELECT score::jsonb FROM encrypted_v3
      WHERE score > $1::jsonb::eql_v3.query_integer_ord_ore
      ORDER BY eql_v3.ord_term_ore(score) ASC
      `,
      [operand],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.score })),
    })
    expect(decrypted).toEqual([20, 30])
  })

  test('range: a query_integer_ord_ope operand matches plaintext order', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        { plaintext: 10, column: 'rank', table: 'v3pg' },
        { plaintext: 20, column: 'rank', table: 'v3pg' },
        { plaintext: 30, column: 'rank', table: 'v3pg' },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted_v3 (rank) VALUES ($1::jsonb), ($2::jsonb), ($3::jsonb)',
      ciphertexts,
    )

    const operand = await encryptQuery(protectClient, {
      plaintext: 25,
      column: 'rank',
      table: 'v3pg',
      indexType: 'ope',
    })
    expect(Object.keys(operand as object).sort()).toEqual(
      integerOrdOpeQueryKeys,
    )

    const res: QueryResult<{ rank: EncryptedPayload }> = await pg.query(
      `
      SELECT rank::jsonb FROM encrypted_v3
      WHERE rank < $1::jsonb::eql_v3.query_integer_ord_ope
      ORDER BY eql_v3.ord_term(rank) ASC
      `,
      [operand],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.rank })),
    })
    expect(decrypted).toEqual([10, 20])
  })

  test('match: a query_text_search_ore operand finds rows containing the term', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: 'the quick brown fox',
          column: 'bio',
          table: 'v3pg',
        },
        {
          plaintext: 'a lazy dog sleeps',
          column: 'bio',
          table: 'v3pg',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted_v3 (bio) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    // The operand carries the FULL text_search_ore term set (hm + ob + bf),
    // whichever indexType was queried — the bf term drives `@@` here (eql
    // 3.0.1 moved fuzzy bloom matching from `@>` to the dedicated `@@`
    // operator; `@>`/`<@` remain jsonb/SteVec containment).
    const operand = await encryptQuery(protectClient, {
      plaintext: 'quick',
      column: 'bio',
      table: 'v3pg',
      indexType: 'match',
    })
    expect(Object.keys(operand as object).sort()).toEqual(
      textSearchOreQueryKeys,
    )

    const res: QueryResult<{ bio: EncryptedPayload }> = await pg.query(
      `
      SELECT bio::jsonb FROM encrypted_v3
      WHERE bio @@ $1::jsonb::eql_v3.query_text_search_ore
      `,
      [operand],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.bio })),
    })
    expect(decrypted).toEqual(['the quick brown fox'])
  })

  test('containment: a query_json needle finds the matching document', async () => {
    const ciphertexts = await encryptBulk(protectClient, {
      plaintexts: [
        {
          plaintext: { role: 'admin', level: 3 },
          column: 'profile',
          table: 'v3pg',
        },
        {
          plaintext: { role: 'viewer', level: 1 },
          column: 'profile',
          table: 'v3pg',
        },
      ],
    })

    await pg.query(
      'INSERT INTO encrypted_v3 (profile) VALUES ($1::jsonb), ($2::jsonb)',
      ciphertexts,
    )

    const needle = await encryptQuery(protectClient, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3pg',
      indexType: 'ste_vec',
    })

    const res: QueryResult<{ profile: EncryptedPayload }> = await pg.query(
      `
      SELECT profile::jsonb FROM encrypted_v3
      WHERE profile @> $1::jsonb::eql_v3.query_json
      `,
      [needle],
    )

    const decrypted = await decryptBulk(protectClient, {
      ciphertexts: res.rows.map((row) => ({ ciphertext: row.profile })),
    })
    expect(decrypted).toEqual([{ role: 'admin', level: 3 }])
  })

  test('selector: the bare selector hash extracts the matching entry', async () => {
    const profile = { role: 'admin', level: 3 }
    const ciphertext = await encrypt(protectClient, {
      plaintext: profile,
      column: 'profile',
      table: 'v3pg',
    })

    await pg.query('INSERT INTO encrypted_v3 (profile) VALUES ($1::jsonb)', [
      ciphertext,
    ])

    const selector = await encryptQuery(protectClient, {
      plaintext: '$.role',
      column: 'profile',
      table: 'v3pg',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector',
    })
    expect(selector).toBeTypeOf('string')

    // `->` has text and integer overloads, so pin the argument type. The
    // extracted jsonb_entry carries the selector it matched on.
    const res: QueryResult<{ entry: EncryptedPayload & { s: string } }> =
      await pg.query(
        `
        SELECT (profile -> $1::text)::jsonb AS entry FROM encrypted_v3
        WHERE profile -> $1::text IS NOT NULL
        `,
        [selector],
      )

    expect(res.rowCount).toBe(1)
    expect(res.rows[0].entry.s).toBe(selector)
    expect(
      await decrypt(protectClient, { ciphertext: res.rows[0].entry }),
    ).toBe('admin')
  })
})
