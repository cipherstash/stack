import 'dotenv/config'

import { createClient } from '@supabase/supabase-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import { encryptedSupabaseV3 } from '@/supabase'
import { installEqlV3IfNeeded } from './helpers/eql-v3'

// Mirror of supabase.test.ts for EQL v3 native domains. Needs a live Supabase
// project, so the suite is skipped unless SUPABASE_URL, SUPABASE_ANON_KEY, and
// DATABASE_URL are all set (plus the CS_* credentials Encryption() needs —
// same as every live suite).
//
// MANUAL PREREQUISITE (same class of step v2 needs for eql_v2): the `eql_v3`
// schema must be added to the Supabase dashboard's **Exposed schemas**
// (Settings → API → Exposed schemas). Without it the custom operators on the
// eql_v3.* domains are not on PostgREST's search_path and bare `col = term`
// filters silently fall back to base jsonb comparison — wrong results, no
// error. The grants themselves are applied automatically by
// installEqlV3IfNeeded below.
const SUPABASE_ENABLED = Boolean(
  process.env.SUPABASE_URL &&
    process.env.SUPABASE_ANON_KEY &&
    process.env.DATABASE_URL,
)

const supabase = SUPABASE_ENABLED
  ? createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_ANON_KEY!)
  : (undefined as unknown as ReturnType<typeof createClient>)

// include_original: false on the match index is load-bearing for the live
// like/ilike tests: v3 filter operands are full storage envelopes (every
// eql_v3 domain CHECK requires the storage keys), and with include_original
// the operand's bloom would carry the whole pattern as an extra token that
// only matches when the pattern equals the stored value.
const table = encryptedTable('protect-ci-v3', {
  email: types.TextSearch('email').freeTextSearch({ include_original: false }),
  age: types.IntegerOrd('age'),
  registeredAt: types.TimestampOrd('registered_at'),
})

type ProtectCiV3Row = {
  id: number
  email: string
  age: number
  registeredAt: Date
  otherField: string
  test_run_id: string
}

const TEST_RUN_ID = `test-run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

const insertedIds: number[] = []

beforeAll(async () => {
  if (!SUPABASE_ENABLED) return

  const sql = postgres(process.env.DATABASE_URL as string, { prepare: false })
  try {
    // Supabase-aware install: opclass-stripped bundle + eql_v3 grants for the
    // anon / authenticated / service_role roles.
    await installEqlV3IfNeeded(sql, { supabase: true })

    await sql`
      CREATE TABLE IF NOT EXISTS "protect-ci-v3" (
        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        email eql_v3.text_search,
        age eql_v3.integer_ord,
        registered_at eql_v3.timestamp_ord,
        "otherField" TEXT,
        created_at TIMESTAMP DEFAULT NOW(),
        test_run_id TEXT
      )
    `
    await sql`GRANT ALL ON "protect-ci-v3" TO anon, authenticated, service_role`
    await sql`NOTIFY pgrst, 'reload schema'`
  } finally {
    await sql.end()
  }

  const { error } = await supabase
    .from('protect-ci-v3')
    .delete()
    .eq('test_run_id', TEST_RUN_ID)

  if (error) {
    console.warn(`[protect]: Failed to clean up test data: ${error.message}`)
  }
}, 60000)

afterAll(async () => {
  if (!SUPABASE_ENABLED) return
  if (insertedIds.length > 0) {
    const { error } = await supabase
      .from('protect-ci-v3')
      .delete()
      .in('id', insertedIds)
    if (error) {
      console.error(`[protect]: Failed to clean up test data: ${error.message}`)
    }
  }
}, 30000)

describe.skipIf(!SUPABASE_ENABLED)(
  'supabase (encryptedSupabaseV3 wrapper, eql_v3 domains)',
  () => {
    async function makeInstance() {
      const client = await Encryption({ schemas: [table] })
      return encryptedSupabaseV3({
        encryptionClient: client,
        supabaseClient: supabase,
      })
    }

    it('inserts and selects an encrypted text_search value', async () => {
      const es = await makeInstance()
      const plaintext = 'hello-v3@example.com'

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert({ email: plaintext, test_run_id: TEST_RUN_ID })
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(insertedData![0].id)

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, email')
        .eq('id', insertedData![0].id)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].email).toBe(plaintext)
    }, 30000)

    it('round-trips a model including a Date column (reconstructRow parity)', async () => {
      const es = await makeInstance()
      const registeredAt = new Date('2026-03-04T05:06:07.000Z')
      const model = {
        email: 'dates-v3@example.com',
        registeredAt,
        otherField: 'not encrypted',
      }

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert({ ...model, test_run_id: TEST_RUN_ID })
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(insertedData![0].id)

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, email, registeredAt, otherField')
        .eq('id', insertedData![0].id)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].email).toBe(model.email)
      expect(data![0].otherField).toBe(model.otherField)
      // Date columns are reconstructed from cast_as, not returned as strings
      expect(data![0].registeredAt).toBeInstanceOf(Date)
      expect(data![0].registeredAt.toISOString()).toBe(
        registeredAt.toISOString(),
      )
    }, 30000)

    it('inserts and selects bulk encrypted models', async () => {
      const es = await makeInstance()
      const models = [
        { email: 'bulk-v3-1@example.com', otherField: 'plain 1' },
        { email: 'bulk-v3-2@example.com', otherField: 'plain 2' },
      ]

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert(models.map((m) => ({ ...m, test_run_id: TEST_RUN_ID })))
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, email, otherField')
        .in(
          'id',
          insertedData!.map((d) => d.id),
        )

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(
        data!.map((d) => ({ email: d.email, otherField: d.otherField })),
      ).toEqual(models)
    }, 30000)

    it('filters a text_search column by equality (full-envelope operand)', async () => {
      const es = await makeInstance()
      const target = `eq-v3-${TEST_RUN_ID}@example.com`

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert([
          { email: target, test_run_id: TEST_RUN_ID },
          {
            email: `other-${TEST_RUN_ID}@example.com`,
            test_run_id: TEST_RUN_ID,
          },
        ])
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      // The equality operand must satisfy the text_search domain CHECK
      // (hm+ob+bf+ciphertext) — a narrowed hm-only term raises 23514. The
      // adapter sends the full envelope; the eq operator matches by hmac.
      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, email')
        .eq('email', target)
        .eq('test_run_id', TEST_RUN_ID)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].email).toBe(target)
    }, 30000)

    it('free-text searches a text_search column via like → cs (bloom containment)', async () => {
      const es = await makeInstance()
      const needle = `ftx${TEST_RUN_ID.slice(-6)}`

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert([
          { email: `alpha-${needle}@example.com`, test_run_id: TEST_RUN_ID },
          { email: `beta-nomatch@example.com`, test_run_id: TEST_RUN_ID },
        ])
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, email')
        .like('email', needle)
        .eq('test_run_id', TEST_RUN_ID)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].email).toContain(needle)
    }, 30000)

    it('filters an integer_ord column by equality', async () => {
      const es = await makeInstance()

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert([
          { age: 37, test_run_id: TEST_RUN_ID },
          { age: 42, test_run_id: TEST_RUN_ID },
        ])
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, age')
        .eq('age', 37)
        .eq('test_run_id', TEST_RUN_ID)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].age).toBe(37)
    }, 30000)

    // First-of-its-kind coverage: the v2 suite historically had no encrypted
    // range test on Supabase (a matching v2 range test now lives in
    // supabase.test.ts). Real ORE terms require live ZeroKMS, hence the same
    // env gating as the rest of the suite. Assert range FILTERING only —
    // ORDER BY on the encrypted column is unsupported on Supabase (no
    // operator families).
    it('filters an integer_ord column by range (gte/lte)', async () => {
      const es = await makeInstance()

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert([
          { age: 10, test_run_id: TEST_RUN_ID },
          { age: 25, test_run_id: TEST_RUN_ID },
          { age: 90, test_run_id: TEST_RUN_ID },
        ])
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, age')
        .gte('age', 20)
        .lte('age', 30)
        .eq('test_run_id', TEST_RUN_ID)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].age).toBe(25)
    }, 30000)

    it('filters a timestamp_ord column by range with Date values', async () => {
      const es = await makeInstance()

      const { data: insertedData, error: insertError } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .insert([
          {
            registeredAt: new Date('2026-01-15T00:00:00.000Z'),
            test_run_id: TEST_RUN_ID,
          },
          {
            registeredAt: new Date('2026-06-15T00:00:00.000Z'),
            test_run_id: TEST_RUN_ID,
          },
        ])
        .select('id')

      if (insertError) throw new Error(`[protect]: ${insertError.message}`)
      insertedIds.push(...insertedData!.map((d) => d.id))

      const { data, error } = await es
        .from<typeof table, ProtectCiV3Row>('protect-ci-v3', table)
        .select('id, registeredAt')
        .gte('registeredAt', new Date('2026-05-01T00:00:00.000Z'))
        .eq('test_run_id', TEST_RUN_ID)

      if (error) throw new Error(`[protect]: ${error.message}`)
      expect(data).toHaveLength(1)
      expect(data![0].registeredAt).toBeInstanceOf(Date)
      expect(data![0].registeredAt.toISOString()).toBe(
        '2026-06-15T00:00:00.000Z',
      )
    }, 30000)
  },
)
