/**
 * Live EQL 3.0.2 boundary for encrypted JSON through PostgREST.
 *
 * Storage/decryption remains supported. Querying does not: containment and
 * selector equality require an `eql_v3.query_json` cast PostgREST cannot emit.
 * The adapter must fail before encrypting a storage-shaped operand into a GET
 * URL, while plaintext filters continue to work.
 */

import type { JsonDocument } from '@cipherstash/stack/eql/v3'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { encryptedSupabaseV3 } from '../src/index.js'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'

const TABLE = 'protect_ci_v3_supabase_json'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const sql = postgres(databaseUrl(), { prepare: false })

const docs = encryptedTable(TABLE, {
  payload: types.Json('payload'),
})

const PAYLOAD: JsonDocument = {
  user: { email: 'ada@example.com', role: 'admin' },
  age: 30,
}

type Instance = Awaited<ReturnType<typeof encryptedSupabaseV3>>
type Row = {
  row_key: string
  payload: JsonDocument | null
  test_run_id: string
}

let instance: Instance

beforeAll(async () => {
  await sql.unsafe(`
    CREATE TABLE IF NOT EXISTS public.${TABLE} (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      row_key text NOT NULL,
      test_run_id text NOT NULL,
      payload public.eql_v3_json_search
    )
  `)
  await sql.unsafe(
    `GRANT SELECT, INSERT ON public.${TABLE} TO anon, authenticated`,
  )
  await reloadSchemaCache(sql, TABLE)

  instance = await encryptedSupabaseV3(makePostgrestClient(), {
    schemas: { [TABLE]: docs } as never,
    databaseUrl: databaseUrl(),
  })

  const { error } = await instance.from<Row>(TABLE).insert({
    row_key: 'ada',
    test_run_id: RUN,
    payload: PAYLOAD,
  })
  if (error) throw new Error(`seed insert: ${error.message}`)
}, 120_000)

afterAll(async () => {
  await sql.unsafe(`DELETE FROM public.${TABLE} WHERE test_run_id = '${RUN}'`)
  await sql.end()
})

describe('encrypted JSON storage', () => {
  it('round-trips through a supported plaintext filter', async () => {
    const { data, error } = await instance
      .from<Row>(TABLE)
      .select('row_key, payload')
      .eq('test_run_id', RUN)

    expect(error).toBeNull()
    expect(data).toEqual([{ row_key: 'ada', payload: PAYLOAD }])
  })
})

describe('EQL 3.0.2 PostgREST query-domain boundary', () => {
  it('fails encrypted JSON operators before building a request', () => {
    const from = () =>
      instance.from<Row>(TABLE).select('row_key').eq('test_run_id', RUN)

    expect(() => from().contains('payload', { age: 30 })).toThrow(
      /EQL 3\.0\.2\+.*query_\* cast.*PostgREST/s,
    )
    expect(() => from().selectorEq('payload', '$.age', 30)).toThrow(
      /EQL 3\.0\.2\+/,
    )
    expect(() => from().selectorNe('payload', '$.age', 30)).toThrow(
      /EQL 3\.0\.2\+/,
    )
  })

  it('also blocks raw cs filters before sending a storage envelope', async () => {
    const { error, status } = await instance
      .from<Row>(TABLE)
      .select('row_key')
      .filter('payload', 'cs', { age: 30 })

    expect(status).toBe(500)
    expect(error?.message).toMatch(/EQL 3\.0\.2\+.*PostgREST/s)
  })
})
