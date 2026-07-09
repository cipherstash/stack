import 'dotenv/config'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { factoryForDomain } from '@/eql/v3/domain-registry'
import { introspect } from '@/supabase/introspect'
import {
  assertModelledDomains,
  synthesizeTables,
} from '@/supabase/schema-builder'
import { installEqlV3IfNeeded } from './helpers/eql-v3'
import { describeLivePgOnly, LIVE_PG_ENABLED } from './helpers/live-gate'

const databaseUrl = process.env.DATABASE_URL
const sql = LIVE_PG_ENABLED
  ? postgres(databaseUrl as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const MODELLED = 'protect_ci_v3_introspect'
const UNMODELLED = 'protect_ci_v3_unmodelled'

beforeAll(async () => {
  if (!LIVE_PG_ENABLED) return
  await installEqlV3IfNeeded(sql)
  await sql.unsafe(`DROP TABLE IF EXISTS ${MODELLED}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${UNMODELLED}`)
  await sql.unsafe(`
    CREATE TABLE ${MODELLED} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      email public.text_search NOT NULL,
      amount public.integer_ord NOT NULL,
      note TEXT,
      meta jsonb
    )
  `)
  // Columns typed with EQL domains that have NO types factory.
  await sql.unsafe(`
    CREATE TABLE ${UNMODELLED} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      score public.integer_ord_ope NOT NULL,
      doc public.json
    )
  `)
}, 30000)

afterAll(async () => {
  if (!LIVE_PG_ENABLED) return
  await sql.unsafe(`DROP TABLE IF EXISTS ${MODELLED}`)
  await sql.unsafe(`DROP TABLE IF EXISTS ${UNMODELLED}`)
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
    expect(domains.email).toBe('text_search')
    expect(domains.amount).toBe('integer_ord')
    // Plaintext + plain jsonb → NULL (udt_name is jsonb for all of these).
    expect(domains.id).toBeNull()
    expect(domains.note).toBeNull()
    expect(domains.meta).toBeNull()
  }, 30000)

  it('round-trips the domain → builder mapping via synthesizeTables', async () => {
    const { tables, eqlDomains } = await introspect(databaseUrl as string)
    // Sanity: the modelled domains are recognised as EQL domains (by COMMENT).
    expect(eqlDomains.has('text_search')).toBe(true)
    expect(eqlDomains.has('integer_ord')).toBe(true)

    const { tables: synth, allColumns } = synthesizeTables(tables)
    const table = synth.get(MODELLED)
    expect(Object.keys(table!.columnBuilders).sort()).toEqual([
      'amount',
      'email',
    ])
    expect(table!.columnBuilders.email.getEqlType()).toBe('public.text_search')
    expect(table!.columnBuilders.amount.getEqlType()).toBe('public.integer_ord')
    expect(allColumns.get(MODELLED)).toEqual([
      'id',
      'email',
      'amount',
      'note',
      'meta',
    ])
  }, 30000)

  it('detects unmodelled EQL domains (by COMMENT) and the guard rejects them', async () => {
    const { tables, eqlDomains } = await introspect(databaseUrl as string)

    // The COMMENT predicate recognises these as EQL domains...
    expect(eqlDomains.has('integer_ord_ope')).toBe(true)
    expect(eqlDomains.has('json')).toBe(true)
    // ...and they have no types factory (genuinely unmodelled)...
    expect(factoryForDomain('integer_ord_ope')).toBeUndefined()
    expect(factoryForDomain('json')).toBeUndefined()

    // Scope the guard to THIS test's tables. `introspect` returns every table in
    // `public`, and a developer's DATABASE_URL may already carry an unmodelled
    // EQL column of its own — the assertion would then pass for the wrong
    // reason, or fail naming a domain this test never created.
    const modelledOnly = tables.filter((t) => t.tableName === MODELLED)
    const scoped = tables.filter(
      (t) => t.tableName === MODELLED || t.tableName === UNMODELLED,
    )
    expect(modelledOnly).toHaveLength(1)
    expect(scoped).toHaveLength(2)

    // The modelled table alone must NOT trip the guard.
    expect(() => assertModelledDomains(modelledOnly, eqlDomains)).not.toThrow()

    // ...and the unmodelled one throws, naming the offending column/domain.
    expect(() => assertModelledDomains(scoped, eqlDomains)).toThrow(
      /integer_ord_ope|public\.json/,
    )
  }, 30000)
})
