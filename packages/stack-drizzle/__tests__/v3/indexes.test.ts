import type { SQL } from 'drizzle-orm'
import {
  getTableConfig,
  integer,
  PgDialect,
  pgTable,
} from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { encryptedIndexes } from '../../src/v3/indexes'
import { types } from '../../src/v3/types'

// #753: the integration emitted the encrypted operators but no index DDL, so
// encrypted predicates sequential-scanned by default. `encryptedIndexes`
// derives the functional indexes from the same per-domain capability record
// the operator layer gates on — these tests pin that mapping, the
// `<table>_<column>_<capability>` naming, and the exact extractor expressions
// (index engagement is STRUCTURAL: the expression must match what the
// planner inlines the operators to, so a drifted expression builds a real
// index that never engages).

const dialect = new PgDialect()

interface IndexConfigView {
  name?: string
  method?: string
  columns: unknown[]
}

/** The built index configs for a table, keyed by index name. */
function indexConfigs(table: Parameters<typeof getTableConfig>[0]) {
  const { indexes } = getTableConfig(table)
  const byName = new Map<string, IndexConfigView>()
  for (const idx of indexes) {
    const config = (idx as unknown as { config: IndexConfigView }).config
    expect(config.name).toBeDefined()
    byName.set(config.name as string, config)
  }
  return byName
}

function renderedExpression(config: IndexConfigView): string {
  expect(config.columns).toHaveLength(1)
  return dialect.sqlToQuery(config.columns[0] as SQL).sql
}

describe('encryptedIndexes', () => {
  const users = pgTable(
    'users',
    {
      id: integer('id').primaryKey(),
      email: types.TextEq('email'),
      createdOn: types.DateOrd('created_on'),
      weight: types.IntegerOrdOre('weight'),
      nickname: types.TextMatch('nickname'),
      bio: types.TextSearch('bio'),
      profile: types.Json('profile'),
      notes: types.Text('notes'),
    },
    (t) => encryptedIndexes(t),
  )

  it('emits one index per capability, named <table>_<column>_<capability>', () => {
    const configs = indexConfigs(users)
    expect([...configs.keys()].sort()).toEqual(
      [
        // TextEq: hm
        'users_email_eq',
        // DateOrd: op only — the bundle defines NO eq_term overload for the
        // `_ord` domains; `eql_v3.eq` inlines to `ord_term(a) = ord_term(b)`,
        // so the single ordering btree serves equality AND range. (Also pins
        // the DB column name, `created_on`, over the `createdOn` property.)
        'users_created_on_ord',
        // IntegerOrdOre: ob only — same shape, via ord_term_ore
        'users_weight_ord_ore',
        // TextMatch: bf only
        'users_nickname_match',
        // TextSearch: hm + op + bf
        'users_bio_eq',
        'users_bio_ord',
        'users_bio_match',
        // Json: ste_vec
        'users_profile_json',
        // `id` (plain integer) and `notes` (storage-only types.Text): nothing
      ].sort(),
    )
  })

  it('uses btree for equality/ordering and gin for match/json', () => {
    const configs = indexConfigs(users)
    expect(configs.get('users_email_eq')?.method).toBe('btree')
    expect(configs.get('users_created_on_ord')?.method).toBe('btree')
    expect(configs.get('users_weight_ord_ore')?.method).toBe('btree')
    expect(configs.get('users_nickname_match')?.method).toBe('gin')
    expect(configs.get('users_profile_json')?.method).toBe('gin')
  })

  it('builds each index over the matching eql_v3 extractor expression', () => {
    const configs = indexConfigs(users)
    const cases: Array<[string, string]> = [
      ['users_email_eq', 'eql_v3.eq_term('],
      ['users_created_on_ord', 'eql_v3.ord_term('],
      ['users_weight_ord_ore', 'eql_v3.ord_term_ore('],
      ['users_nickname_match', 'eql_v3.match_term('],
    ]
    for (const [name, expected] of cases) {
      const config = configs.get(name)
      expect(config, name).toBeDefined()
      expect(renderedExpression(config as IndexConfigView), name).toContain(
        expected,
      )
    }
  })

  it('rides the jsonb_path_ops opclass inside the json expression', () => {
    const configs = indexConfigs(users)
    const rendered = renderedExpression(
      configs.get('users_profile_json') as IndexConfigView,
    )
    expect(rendered).toContain('eql_v3.to_ste_vec_query(')
    expect(rendered).toContain('::jsonb) jsonb_path_ops')
  })

  it('references the column, not a bound parameter, in every expression', () => {
    // A column interpolated into sql`` must render as an identifier; if it
    // ever rendered as a placeholder the index DDL would be unbuildable.
    const configs = indexConfigs(users)
    for (const [name, config] of configs) {
      const query = dialect.sqlToQuery(config.columns[0] as SQL)
      expect(query.params, name).toEqual([])
      expect(query.sql, name).toMatch(/"[a-z_]+"/)
    }
  })

  it('emits nothing for a table with no encrypted columns', () => {
    let captured: unknown[] = []
    pgTable('plain', { id: integer('id').primaryKey() }, (t) => {
      captured = encryptedIndexes(t)
      return captured
    })
    expect(captured).toEqual([])
  })

  it('ignores non-column values defensively', () => {
    expect(encryptedIndexes({})).toEqual([])
    expect(encryptedIndexes({ nope: 42, other: { name: 'x' } })).toEqual([])
  })
})
