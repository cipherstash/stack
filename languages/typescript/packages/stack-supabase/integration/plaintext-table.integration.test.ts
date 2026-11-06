import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { databaseUrl } from '@cipherstash/test-kit'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { encryptedSupabase } from '../src/index.js'
import { makePostgrestClient, reloadSchemaCache } from './helpers/pgrest'

/**
 * Reads and returning mutations on a table with NO encrypted columns.
 *
 * Such a table is reachable through `from()` but is deliberately left out of
 * `Encryption({ schemas })`, and the real client refuses a model operation on a
 * table it was not initialized with. Every read of one used to fail with
 * "decryptModel received a table this client was not initialized with" — a
 * failure the unit suites could not see, because their encryption double
 * ignores the table argument. This suite runs the real client.
 *
 * Both construction modes, because the plaintext table reaches the builder by
 * a different route in each: discovered by introspection, or declared with an
 * empty column set.
 */
const suffix = Math.random().toString(36).slice(2, 8)
const SECRETS = `v3_it_secrets_${suffix}`
const AUDIT = `v3_it_audit_${suffix}`

const secrets = encryptedTable(SECRETS, { email: types.TextEq('email') })
const audit = encryptedTable(AUDIT, {})

const sql = postgres(databaseUrl(), { prepare: false })

beforeAll(async () => {
  await sql.unsafe(`DROP TABLE IF EXISTS ${SECRETS}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${AUDIT}`)
  // The encrypted table is not under test. It is here because introspection
  // mode refuses a database with no EQL v3 column at all, and this suite must
  // not depend on another suite's table still existing.
  await sql.unsafe(`
    CREATE TABLE ${SECRETS} (
      row_key TEXT PRIMARY KEY,
      email public.eql_v3_text_eq
    )
  `)
  await sql.unsafe(`
    CREATE TABLE ${AUDIT} (
      row_key TEXT PRIMARY KEY,
      action TEXT NOT NULL
    )
  `)
  await sql.unsafe(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ${SECRETS}, ${AUDIT} TO anon, authenticated`,
  )
  await reloadSchemaCache(sql, SECRETS)
  await reloadSchemaCache(sql, AUDIT)
}, 300_000)

afterAll(async () => {
  await sql.unsafe(`DROP TABLE IF EXISTS ${SECRETS}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${AUDIT}`)
  await sql.end()
})

describe.each([
  [
    'introspection mode',
    () =>
      encryptedSupabase(makePostgrestClient(), { databaseUrl: databaseUrl() }),
  ],
  [
    'declared mode',
    () =>
      encryptedSupabase(makePostgrestClient(), {
        schemas: { [SECRETS]: secrets, [AUDIT]: audit } as never,
      }),
  ],
] as const)('plaintext table — %s', (mode, build) => {
  // biome-ignore lint/suspicious/noExplicitAny: the row type is not declared here
  let instance: any
  const key = mode.startsWith('introspection') ? 'i' : 'd'

  beforeAll(async () => {
    instance = await build()
    await sql.unsafe(`DELETE FROM ${AUDIT}`)
  }, 300_000)

  it('returns the inserted row from a returning insert', async () => {
    const { data, error } = await instance
      .from(AUDIT)
      .insert({ row_key: `${key}1`, action: 'login' })
      .select('row_key, action')

    expect(error).toBeNull()
    expect(data).toEqual([{ row_key: `${key}1`, action: 'login' }])
  })

  it('returns bulk-inserted rows', async () => {
    const rows = [
      { row_key: `${key}2`, action: 'logout' },
      { row_key: `${key}3`, action: 'login' },
    ]
    const { data, error } = await instance
      .from(AUDIT)
      .insert(rows)
      .select('row_key, action')

    expect(error).toBeNull()
    expect(data).toEqual(rows)
  })

  it('reads every row', async () => {
    const { data, error } = await instance
      .from(AUDIT)
      .select('row_key, action')
      .order('row_key', { ascending: true })

    expect(error).toBeNull()
    expect(data).toEqual([
      { row_key: `${key}1`, action: 'login' },
      { row_key: `${key}2`, action: 'logout' },
      { row_key: `${key}3`, action: 'login' },
    ])
  })

  it('reads a single row with a plaintext filter', async () => {
    const { data, error } = await instance
      .from(AUDIT)
      .select('row_key, action')
      .eq('row_key', `${key}2`)
      .single()

    expect(error).toBeNull()
    expect(data).toEqual({ row_key: `${key}2`, action: 'logout' })
  })

  it('still round-trips the encrypted table on the same instance', async () => {
    const { data, error } = await instance
      .from(SECRETS)
      .insert({ row_key: `${key}1`, email: 'a@example.com' })
      .select('row_key, email')

    expect(error).toBeNull()
    expect(data).toEqual([{ row_key: `${key}1`, email: 'a@example.com' }])
  })

  // Declared mode refuses `select('*')` outright: with no introspection there
  // is no column list to expand it from.
  it.skipIf(mode === 'declared mode')('reads with select("*")', async () => {
    const { data, error } = await instance
      .from(AUDIT)
      .select('*')
      .eq('row_key', `${key}1`)

    expect(error).toBeNull()
    expect(data).toEqual([{ row_key: `${key}1`, action: 'login' }])
  })
})
