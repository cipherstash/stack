import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { factoryForDomain } from '@/eql/v3/domain-registry'
import { introspect } from '@/supabase/introspect'
import { synthesizeTables } from '@/supabase/schema-builder'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import { describeLivePgOnly, LIVE_PG_ENABLED } from './helpers/live-gate'

const databaseUrl = process.env.DATABASE_URL
const sql = LIVE_PG_ENABLED
  ? postgres(databaseUrl as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const MODELLED = 'protect_ci_v3_introspect'
const UNMODELLED = 'protect_ci_v3_unmodelled'
const USER_DOMAIN = 'protect_ci_v3_user_json'

beforeAll(async () => {
  if (!LIVE_PG_ENABLED) return
  await installEqlV3IfNeeded(sql)
  await sql.unsafe(`DROP TABLE IF EXISTS ${MODELLED}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${UNMODELLED}`)
  await sql.unsafe(`
    CREATE TABLE ${MODELLED} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      email public.eql_v3_text_search NOT NULL,
      amount public.eql_v3_integer_ord NOT NULL,
      note TEXT,
      meta jsonb
    )
  `)
  // A user's OWN jsonb domain, with no EQL comment. It must never be reported
  // as unmodelled — it is an ordinary plaintext passthrough.
  await sql.unsafe(`DROP DOMAIN IF EXISTS public.${USER_DOMAIN}`)
  await sql.unsafe(`CREATE DOMAIN public.${USER_DOMAIN} AS jsonb`)
  // Columns typed with EQL domains that have NO types factory.
  await sql.unsafe(`
    CREATE TABLE ${UNMODELLED} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      score public.eql_v3_integer_ord_ope NOT NULL,
      doc public.eql_v3_json,
      own public.${USER_DOMAIN}
    )
  `)
}, 30000)

afterAll(async () => {
  if (!LIVE_PG_ENABLED) return
  await sql.unsafe(`DROP TABLE IF EXISTS ${MODELLED}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${UNMODELLED}`)
  await sql.unsafe(`DROP DOMAIN IF EXISTS public.${USER_DOMAIN}`)
  await sql.end()
}, 30000)

describeLivePgOnly('eql_v3 supabase introspection', () => {
  it('detects EQL v3 domains and classifies plaintext columns', async () => {
    const { tables } = await introspect(databaseUrl as string)
    const table = tables.find((t) => t.tableName === MODELLED)
    expect(table).toBeDefined()
    const domains = Object.fromEntries(
      table!.columns.map((c) => [c.columnName, c.domainName]),
    )
    expect(domains.email).toBe('eql_v3_text_search')
    expect(domains.amount).toBe('eql_v3_integer_ord')
    // Plaintext + plain jsonb → NULL (udt_name is jsonb for all of these).
    expect(domains.id).toBeNull()
    expect(domains.note).toBeNull()
    expect(domains.meta).toBeNull()
  }, 30000)

  it('round-trips the domain → builder mapping via synthesizeTables', async () => {
    const { tables } = await introspect(databaseUrl as string)

    const { tables: synth, allColumns } = synthesizeTables(tables)
    const table = synth.get(MODELLED)
    expect(Object.keys(table!.columnBuilders).sort()).toEqual([
      'amount',
      'email',
    ])
    expect(table!.columnBuilders.email.getEqlType()).toBe(
      'public.eql_v3_text_search',
    )
    expect(table!.columnBuilders.amount.getEqlType()).toBe(
      'public.eql_v3_integer_ord',
    )
    expect(allColumns.get(MODELLED)).toEqual([
      'id',
      'email',
      'amount',
      'note',
      'meta',
    ])
  }, 30000)

  // The three-way classification now lives entirely in the SQL predicate of
  // `UNMODELLED_COLUMNS_QUERY`: EQL-by-COMMENT, and not in `DOMAIN_REGISTRY`.
  // These prove it against a real catalog — nothing else does.
  it('reports unmodelled EQL columns, keyed by table', async () => {
    const { unmodelled } = await introspect(databaseUrl as string)

    // Sanity: these really are EQL domains with no types factory.
    expect(factoryForDomain('integer_ord_ope')).toBeUndefined()
    expect(factoryForDomain('json')).toBeUndefined()

    const offenders = unmodelled.get(UNMODELLED)
    expect(offenders).toBeDefined()
    expect(offenders?.map((c) => c.columnName).sort()).toEqual(['doc', 'score'])
    expect(offenders?.find((c) => c.columnName === 'score')?.domainName).toBe(
      'eql_v3_integer_ord_ope',
    )
  }, 30000)

  it('does not report a fully-modelled table', async () => {
    const { unmodelled } = await introspect(databaseUrl as string)
    expect(unmodelled.has(MODELLED)).toBe(false)
  }, 30000)

  it("does not report a user's own jsonb domain as unmodelled", async () => {
    const { unmodelled } = await introspect(databaseUrl as string)
    // `own` carries a public domain with NO EQL comment → plaintext, not a leak.
    const offenders = unmodelled.get(UNMODELLED) ?? []
    expect(offenders.map((c) => c.columnName)).not.toContain('own')
  }, 30000)

  // The precondition that makes the `from()` guard load-bearing: an unmodelled
  // column is silently dropped from the encrypt config, yet stays in
  // `allColumns` — so `select('*')` would select it and return raw ciphertext.
  it('synthesizeTables drops an unmodelled column but allColumns keeps it', async () => {
    const { tables } = await introspect(databaseUrl as string)
    const { tables: synth, allColumns } = synthesizeTables(tables)

    expect(Object.keys(synth.get(UNMODELLED)!.columnBuilders)).toEqual([])
    expect(allColumns.get(UNMODELLED)).toContain('score')
    expect(allColumns.get(UNMODELLED)).toContain('doc')
  }, 30000)
})
