import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { encryptedSupabaseV3 } from '@/supabase'
import {
  makePostgrestClient,
  reloadSchemaCache,
} from '../../__tests__/helpers/pgrest'

/**
 * `Date` reconstruction across every way PostgREST can key a result row.
 *
 * Not expressible through the family driver: it is about the SELECT string, not
 * about a query operation, and only the Supabase adapter has the concept. The
 * driver proves the operations; this proves the projection.
 *
 * A decrypted date-like column arrives as an ISO string, and the adapter rebuilds
 * the `Date` by looking up the column's `cast_as`. That lookup is keyed by DB
 * column name, so it needs a map from the ROW KEY back to the DB column — and the
 * row key is whatever PostgREST chose, which is one of three things:
 *
 *   .select('createdAt')      -> keyed `createdAt`  (the JS property; renamed)
 *   .select('created_at')     -> keyed `created_at` (the raw DB name)
 *   .select('ts:createdAt')   -> keyed `ts`         (a caller-chosen alias)
 *
 * The third case regressed: `selectKeyToDb` was dropped from `buildSelectString`,
 * so an aliased date column came back as a string where the typed surface
 * promises a `Date`.
 */
const TABLE = `v3_it_alias_${Math.random().toString(36).slice(2, 8)}`
const CREATED = new Date('2026-01-02T03:04:05.000Z')

// `createdAt` -> `created_at` is the rename the aliasing `prop:db_name::jsonb`
// select exists for; a table whose property equals its DB name cannot express it.
const rows = encryptedTable(TABLE, {
  createdAt: types.Timestamp('created_at'),
  bornOn: types.Date('born_on'),
})

const sql = postgres(databaseUrl(), { prepare: false })
// biome-ignore lint/suspicious/noExplicitAny: the row type varies per select
let instance: any

beforeAll(async () => {
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.unsafe(`
    CREATE TABLE ${TABLE} (
      row_key TEXT PRIMARY KEY,
      created_at public.eql_v3_timestamp,
      born_on public.eql_v3_date
    )
  `)
  await sql.unsafe(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${TABLE} TO anon, authenticated`,
  )
  await reloadSchemaCache(sql, TABLE)

  instance = await encryptedSupabaseV3(makePostgrestClient(), {
    schemas: { [TABLE]: rows } as never,
    databaseUrl: databaseUrl(),
  })

  const { error } = await instance
    .from(TABLE)
    .insert({ row_key: 'a', createdAt: CREATED, bornOn: CREATED })
  if (error) throw new Error(`insert: ${error.message}`)
}, 300_000)

afterAll(async () => {
  await sql.unsafe(`DROP TABLE IF EXISTS ${TABLE}`)
  await sql.end()
})

it('reconstructs a Date keyed by the JS property name', async () => {
  const { data, error } = await instance
    .from(TABLE)
    .select('row_key, createdAt')

  expect(error).toBeNull()
  expect(data[0].createdAt).toBeInstanceOf(Date)
  expect((data[0].createdAt as Date).toISOString()).toBe(CREATED.toISOString())
})

it('reconstructs a Date keyed by the raw DB column name', async () => {
  const { data, error } = await instance
    .from(TABLE)
    .select('row_key, created_at')

  expect(error).toBeNull()
  expect(data[0].created_at).toBeInstanceOf(Date)
})

it('reconstructs a Date keyed by a caller-chosen alias', async () => {
  const { data, error } = await instance
    .from(TABLE)
    .select('row_key, ts:createdAt')

  expect(error).toBeNull()
  expect(data[0].ts).toBeInstanceOf(Date)
  expect((data[0].ts as Date).toISOString()).toBe(CREATED.toISOString())
})

it('reconstructs a Date under an alias of the raw DB column name', async () => {
  const { data, error } = await instance
    .from(TABLE)
    .select('row_key, at:created_at')

  expect(error).toBeNull()
  expect(data[0].at).toBeInstanceOf(Date)
})

// `date` and `timestamp` are separate `cast_as` values; both are date-like, and
// both must be reconstructed under an alias.
it('reconstructs an aliased date column, not just timestamp', async () => {
  const { data, error } = await instance.from(TABLE).select('row_key, d:bornOn')

  expect(error).toBeNull()
  expect(data[0].d).toBeInstanceOf(Date)
})

it('expands select(*) with every date column reconstructed', async () => {
  const { data, error } = await instance.from(TABLE).select('*')

  expect(error).toBeNull()
  expect(data[0].createdAt).toBeInstanceOf(Date)
  expect(data[0].bornOn).toBeInstanceOf(Date)
})
