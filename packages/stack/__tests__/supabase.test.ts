import 'dotenv/config'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'
import { encryptedSupabase } from '@/supabase'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { createClient } from '@supabase/supabase-js'

if (!process.env.SUPABASE_URL) {
  throw new Error('Missing env.SUPABASE_URL')
}
if (!process.env.SUPABASE_ANON_KEY) {
  throw new Error('Missing env.SUPABASE_ANON_KEY')
}
if (!process.env.DATABASE_URL) {
  throw new Error('Missing env.DATABASE_URL — needed for fixture setup DDL')
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY,
)

const table = encryptedTable('protect-ci', {
  encrypted: encryptedColumn('encrypted').freeTextSearch().equality(),
  age: encryptedColumn('age').dataType('number').equality(),
  score: encryptedColumn('score').dataType('number').equality(),
})

// Row type for the protect-ci table
type ProtectCiRow = {
  id: number
  encrypted: string
  age: number
  score: number
  otherField: string
  test_run_id: string
}

// Unique identifier for this test run to isolate data from concurrent test runs
// This is stored in a dedicated test_run_id column to avoid polluting test data
const TEST_RUN_ID = `test-run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`

// Track all inserted IDs for cleanup
const insertedIds: number[] = []

beforeAll(async () => {
  // Idempotent fixture setup. The `protect-ci` table is shared across the
  // drizzle + protect/supabase + stack/supabase integration suites; each
  // suite's beforeAll runs the same CREATE TABLE so a fresh database is
  // ready without manual DBA work. The schema is the union of every
  // column those suites read or write.
  const sql = postgres(process.env.DATABASE_URL as string, { prepare: false })
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS "protect-ci" (
        id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
        email eql_v2_encrypted,
        age eql_v2_encrypted,
        score eql_v2_encrypted,
        profile eql_v2_encrypted,
        encrypted eql_v2_encrypted,
        "otherField" TEXT,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        test_run_id TEXT
      )
    `
    // Backfill any column added after the table was first created on a
    // long-lived CI database. CREATE TABLE IF NOT EXISTS is a no-op on
    // those, so new columns need an explicit ADD COLUMN IF NOT EXISTS.
    await sql`
      ALTER TABLE "protect-ci" ADD COLUMN IF NOT EXISTS "otherField" TEXT
    `
    // Tell PostgREST to refresh its schema cache so the supabase-js client
    // can see a freshly created table without waiting for the polling
    // interval. No-op on plain Postgres (no listener bound).
    await sql`NOTIFY pgrst, 'reload schema'`
  } finally {
    await sql.end()
  }

  // Clean up any data from this specific test run (safe for concurrent runs)
  const { error } = await supabase
    .from('protect-ci')
    .delete()
    .eq('test_run_id', TEST_RUN_ID)

  if (error) {
    console.warn(`[protect]: Failed to clean up test data: ${error.message}`)
  }
}, 30000)

afterAll(async () => {
  // Clean up all data from this test run
  if (insertedIds.length > 0) {
    const { error } = await supabase
      .from('protect-ci')
      .delete()
      .in('id', insertedIds)
    if (error) {
      console.error(`[protect]: Failed to clean up test data: ${error.message}`)
    }
  }
}, 30000)

describe('supabase (encryptedSupabase wrapper)', () => {
  it('should insert and select encrypted data', async () => {
    const protectClient = await Encryption({ schemas: [table] })
    const eSupabase = encryptedSupabase({
      encryptionClient: protectClient,
      supabaseClient: supabase,
    })

    const plaintext = 'hello world'

    // Insert — auto-encrypts the `encrypted` column, auto-converts to PG composite
    const { data: insertedData, error: insertError } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .insert({
        encrypted: plaintext,
        test_run_id: TEST_RUN_ID,
      })
      .select('id')

    if (insertError) {
      throw new Error(`[protect]: ${insertError.message}`)
    }

    insertedIds.push(insertedData![0].id)

    // Select — auto-adds ::jsonb cast to `encrypted`, auto-decrypts result
    const { data, error } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .select('id, encrypted')
      .eq('id', insertedData![0].id)

    if (error) {
      throw new Error(`[protect]: ${error.message}`)
    }

    expect(data).toHaveLength(1)
    expect(data![0].encrypted).toBe(plaintext)
  }, 30000)

  it('should insert and select encrypted model data', async () => {
    const protectClient = await Encryption({ schemas: [table] })
    const eSupabase = encryptedSupabase({
      encryptionClient: protectClient,
      supabaseClient: supabase,
    })

    const model = {
      encrypted: 'hello world',
      otherField: 'not encrypted',
    }

    // Insert — auto-encrypts `encrypted`, passes `otherField` through
    const { data: insertedData, error: insertError } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .insert({
        ...model,
        test_run_id: TEST_RUN_ID,
      })
      .select('id')

    if (insertError) {
      throw new Error(`[protect]: ${insertError.message}`)
    }

    insertedIds.push(insertedData![0].id)

    // Select — auto-adds ::jsonb to `encrypted`, auto-decrypts
    const { data, error } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .select('id, encrypted, otherField')
      .eq('id', insertedData![0].id)

    if (error) {
      throw new Error(`[protect]: ${error.message}`)
    }

    expect(data).toHaveLength(1)
    expect({
      encrypted: data![0].encrypted,
      otherField: data![0].otherField,
    }).toEqual(model)
  }, 30000)

  it('should insert and select bulk encrypted model data', async () => {
    const protectClient = await Encryption({ schemas: [table] })
    const eSupabase = encryptedSupabase({
      encryptionClient: protectClient,
      supabaseClient: supabase,
    })

    const models = [
      {
        encrypted: 'hello world 1',
        otherField: 'not encrypted 1',
      },
      {
        encrypted: 'hello world 2',
        otherField: 'not encrypted 2',
      },
    ]

    // Bulk insert — auto-encrypts all models
    const { data: insertedData, error: insertError } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .insert(models.map((m) => ({ ...m, test_run_id: TEST_RUN_ID })))
      .select('id')

    if (insertError) {
      throw new Error(`[protect]: ${insertError.message}`)
    }

    insertedIds.push(...insertedData!.map((d) => d.id))

    // Select — auto-decrypts all results
    const { data, error } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .select('id, encrypted, otherField')
      .in(
        'id',
        insertedData!.map((d) => d.id),
      )

    if (error) {
      throw new Error(`[protect]: ${error.message}`)
    }

    expect(
      data!.map((d) => ({
        encrypted: d.encrypted,
        otherField: d.otherField,
      })),
    ).toEqual(models)
  }, 30000)

  it('should insert and query encrypted number data with equality', async () => {
    const protectClient = await Encryption({ schemas: [table] })
    const eSupabase = encryptedSupabase({
      encryptionClient: protectClient,
      supabaseClient: supabase,
    })

    const testAge = 25
    const model = {
      age: testAge,
      otherField: 'not encrypted',
    }

    // Insert — auto-encrypts `age`
    const { data: insertedData, error: insertError } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .insert({
        ...model,
        test_run_id: TEST_RUN_ID,
      })
      .select('id')

    if (insertError) {
      throw new Error(`[protect]: ${insertError.message}`)
    }

    insertedIds.push(insertedData![0].id)

    // Query by encrypted `age` — auto-encrypts the search term
    const { data, error } = await eSupabase
      .from<ProtectCiRow>('protect-ci', table)
      .select('id, age, otherField')
      .eq('age', testAge)
      .eq('test_run_id', TEST_RUN_ID)

    if (error) {
      throw new Error(`[protect]: ${error.message}`)
    }

    // Verify we found our specific row with encrypted age match
    expect(data).toHaveLength(1)
    expect(data![0].age).toBe(testAge)
  }, 30000)
})
