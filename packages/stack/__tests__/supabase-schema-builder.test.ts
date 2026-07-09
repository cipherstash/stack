import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import type { IntrospectionResult } from '@/supabase/introspect'
import {
  assertModelledDomains,
  mergeDeclaredTables,
  synthesizeTables,
} from '@/supabase/schema-builder'

const introspection: IntrospectionResult = [
  {
    tableName: 'users',
    columns: [
      { columnName: 'id', domainName: null },
      { columnName: 'email', domainName: 'text_search' },
      { columnName: 'amount', domainName: 'integer_ord' },
      { columnName: 'note', domainName: null },
      { columnName: 'weird', domainName: 'not_a_domain' }, // unknown → plaintext
    ],
  },
]

describe('synthesizeTables', () => {
  it('builds an EncryptedTable with only the recognised domain columns', () => {
    const { tables } = synthesizeTables(introspection)
    const users = tables.get('users')
    expect(users).toBeDefined()
    expect(Object.keys(users!.columnBuilders).sort()).toEqual([
      'amount',
      'email',
    ])
  })

  it('records the FULL column list (encrypted + plaintext) for select(*)', () => {
    const { allColumns } = synthesizeTables(introspection)
    expect(allColumns.get('users')).toEqual([
      'id',
      'email',
      'amount',
      'note',
      'weird',
    ])
  })

  it('synthesizes a domain column byte-identically to a declared column', () => {
    const { tables } = synthesizeTables(introspection)
    const synthesized = tables.get('users')!.build()
    const declared = encryptedTable('users', {
      email: types.TextSearch('email'),
      amount: types.IntegerOrd('amount'),
    }).build()
    expect(synthesized.columns.email).toEqual(declared.columns.email)
    expect(synthesized.columns.amount).toEqual(declared.columns.amount)
  })

  it('treats an Object.prototype-named domain as plaintext, not a domain', () => {
    // `DOMAIN_REGISTRY['constructor']` would be truthy on a plain object; the
    // null prototype + Object.hasOwn guard keep this column plaintext.
    const prototypeNamed: IntrospectionResult = [
      {
        tableName: 'weird',
        columns: [
          { columnName: 'a', domainName: 'constructor' },
          { columnName: 'b', domainName: '__proto__' },
          { columnName: 'c', domainName: 'toString' },
        ],
      },
    ]
    const { tables, allColumns } = synthesizeTables(prototypeNamed)
    expect(Object.keys(tables.get('weird')!.columnBuilders)).toEqual([])
    expect(allColumns.get('weird')).toEqual(['a', 'b', 'c'])
  })
})

describe('mergeDeclaredTables', () => {
  it('keeps the declared builder instance over the synthesized one', () => {
    const synth = synthesizeTables(introspection)
    const declaredTable = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const merged = mergeDeclaredTables(synth, { users: declaredTable })
    const mergedTable = merged.tables.get('users')!

    // A declared column and its synthesized twin build byte-identically (see
    // above), so instance identity is the only observable proof that the
    // declared builder is the one that survived the merge.
    expect(mergedTable.columnBuilders.email).toBe(
      declaredTable.columnBuilders.email,
    )
    expect(mergedTable.build().columns.amount).toBeDefined()
    expect(merged.allColumns.get('users')).toEqual(
      synth.allColumns.get('users'),
    )
  })

  it('preserves a declared property→DB-name rename', () => {
    const renamed: IntrospectionResult = [
      {
        tableName: 'events',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'created_on', domainName: 'timestamp_ord' },
        ],
      },
    ]
    const synth = synthesizeTables(renamed)
    const declaredTable = encryptedTable('events', {
      createdAt: types.TimestampOrd('created_on'),
    })
    const merged = mergeDeclaredTables(synth, { events: declaredTable })
    const table = merged.tables.get('events')!
    expect(table.buildColumnKeyMap()).toEqual({ createdAt: 'created_on' })
    expect(Object.keys(table.columnBuilders)).toEqual(['createdAt'])
  })
})

describe('assertModelledDomains', () => {
  it('passes when every EQL domain in use is modelled', () => {
    const eqlDomains = new Set(['text_search', 'integer_ord'])
    expect(() => assertModelledDomains(introspection, eqlDomains)).not.toThrow()
  })

  it('throws naming the column + domain for a recognised-but-unmodelled domain', () => {
    const withOpe: IntrospectionResult = [
      {
        tableName: 'metrics',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'score', domainName: 'integer_ord_ope' },
        ],
      },
    ]
    // integer_ord_ope IS an EQL v3 domain, but has no types factory.
    const eqlDomains = new Set(['integer_ord_ope'])
    expect(() => assertModelledDomains(withOpe, eqlDomains)).toThrow(
      /metrics\.score.*integer_ord_ope|integer_ord_ope.*metrics\.score/,
    )
  })

  it('does NOT throw for a user jsonb domain that is not an EQL domain', () => {
    const withUserDomain: IntrospectionResult = [
      {
        tableName: 'docs',
        columns: [{ columnName: 'body', domainName: 'my_json' }],
      },
    ]
    // my_json is NOT in eqlDomains → plaintext passthrough, no throw.
    expect(() => assertModelledDomains(withUserDomain, new Set())).not.toThrow()
  })
})
