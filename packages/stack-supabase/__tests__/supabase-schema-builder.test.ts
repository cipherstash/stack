import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import type { IntrospectionResult } from '../src/introspect'
import { groupUnmodelledRows } from '../src/introspect'
import { mergeDeclaredTables, synthesizeTables } from '../src/schema-builder'

const introspection: IntrospectionResult = [
  {
    tableName: 'users',
    columns: [
      { columnName: 'id', domainName: null },
      { columnName: 'email', domainName: 'eql_v3_text_search' },
      { columnName: 'amount', domainName: 'eql_v3_integer_ord' },
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

  // A DB column may legally be named `__proto__`; `encryptedTable()` rejects
  // such names as JS properties, but nothing constrains the database. On a plain
  // object literal, `builders['__proto__'] = builder` reparents the object
  // instead of adding an own key, so the column disappears — it would then be
  // treated as a plaintext passthrough and its ciphertext returned undecrypted
  // (`decryptModel` skips columns absent from the encrypt config).
  const protoColumn: IntrospectionResult = [
    {
      tableName: 'users',
      columns: [
        { columnName: '__proto__', domainName: 'eql_v3_text_search' },
        { columnName: 'email', domainName: 'eql_v3_text_search' },
      ],
    },
  ]

  it('keeps a column literally named __proto__ as an own builder key', () => {
    const { tables } = synthesizeTables(protoColumn)
    const builders = tables.get('users')!.columnBuilders

    expect(Object.hasOwn(builders, '__proto__')).toBe(true)
    expect(Object.keys(builders).sort()).toEqual(['__proto__', 'email'])
  })

  it('registers a __proto__ column in the encrypt config, not on the prototype', () => {
    const { columns } = synthesizeTables(protoColumn)
      .tables.get('users')!
      .build()

    // The load-bearing assertion: absent from the config, the column is a
    // plaintext passthrough and reads return raw ciphertext.
    expect(Object.hasOwn(columns, '__proto__')).toBe(true)
    expect(Object.keys(columns).sort()).toEqual(['__proto__', 'email'])
  })
})

describe('mergeDeclaredTables', () => {
  // The merge copies synthesized builders across by DB column name. Only the
  // SYNTHESIZED side can carry `__proto__` — `encryptedTable()` rejects it as a
  // declared key (`isReservedTableKey`) — so this is the one path that can
  // reparent the merge target and drop the column from the encrypt config.
  it('copies a synthesized __proto__ column as an own key', () => {
    const protoIntrospection: IntrospectionResult = [
      {
        tableName: 'users',
        columns: [
          { columnName: '__proto__', domainName: 'eql_v3_text_search' },
          { columnName: 'email', domainName: 'eql_v3_text_search' },
        ],
      },
    ]
    const synth = synthesizeTables(protoIntrospection)
    const declaredTable = encryptedTable('users', {
      email: types.TextSearch('email'),
    })

    const merged = mergeDeclaredTables(synth, { users: declaredTable })
    const builders = merged.tables.get('users')!.columnBuilders

    expect(Object.hasOwn(builders, '__proto__')).toBe(true)
    expect(Object.keys(builders).sort()).toEqual(['__proto__', 'email'])
  })

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
          { columnName: 'created_on', domainName: 'eql_v3_timestamp_ord' },
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

  it('merges a declared table absent from introspection as declared-only', () => {
    // Unreachable through `encryptedSupabaseV3` — `verifyDeclaredSchemas` throws
    // on an absent table before the merge runs — but `mergeDeclaredTables` is
    // exported, so the `if (synthesized)` false arm is reachable by any other
    // caller and must not read through to a stale table or throw.
    const synth = synthesizeTables(introspection)
    const declaredTable = encryptedTable('orders', {
      total: types.IntegerOrd('total'),
    })
    const merged = mergeDeclaredTables(synth, { orders: declaredTable })

    expect(Object.keys(merged.tables.get('orders')!.columnBuilders)).toEqual([
      'total',
    ])
    // The absent table contributes no `allColumns`, so `select('*')` on it
    // still throws rather than silently selecting nothing.
    expect(merged.allColumns.get('orders')).toBeUndefined()
    // The introspected table is untouched.
    expect(
      Object.keys(merged.tables.get('users')!.columnBuilders).sort(),
    ).toEqual(['amount', 'email'])
  })
})

// The three-way classification (plaintext / modelled / unmodelled) moved into
// `UNMODELLED_COLUMNS_QUERY`'s predicate, so it is proven against live Postgres
// in `integration/supabase/introspect.integration.test.ts`, not here. What remains client-side is
// the grouping — and, load-bearing, the fact that `synthesizeTables` treats an
// unmodelled column as plaintext (covered above): that is exactly why the
// `from()` guard must be unconditional.
describe('groupUnmodelledRows', () => {
  it('groups rows by table name, preserving row order', () => {
    expect(
      groupUnmodelledRows([
        {
          table_name: 'metrics',
          column_name: 'score',
          domain_name: 'eql_v3_integer_ord_ope',
        },
        {
          table_name: 'audit',
          column_name: 'payload',
          domain_name: 'eql_v3_json_search',
        },
        {
          table_name: 'metrics',
          column_name: 'bucket',
          domain_name: 'eql_v3_text_ord_ope',
        },
      ]),
    ).toEqual(
      new Map([
        [
          'metrics',
          [
            { columnName: 'score', domainName: 'eql_v3_integer_ord_ope' },
            { columnName: 'bucket', domainName: 'eql_v3_text_ord_ope' },
          ],
        ],
        [
          'audit',
          [{ columnName: 'payload', domainName: 'eql_v3_json_search' }],
        ],
      ]),
    )
  })

  it('returns an empty map when nothing is unmodelled', () => {
    expect(groupUnmodelledRows([]).size).toBe(0)
  })
})
