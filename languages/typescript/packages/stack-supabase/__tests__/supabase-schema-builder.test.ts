import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import { describe, expect, it } from 'vitest'
import { ColumnMap } from '../src/column-map'
import type { IntrospectionResult } from '../src/introspect'
import { groupUnmodelledRows } from '../src/introspect'
import { mergeDeclaredTables, synthesizeTables } from '../src/schema-builder'
import { wasmAuthoredV3Table } from './helpers/supabase-mock'

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

describe('ColumnMap recognises v3 columns structurally, not by class identity', () => {
  // tsup emits `EncryptedV3Column` into several bundles: ESM code-splits, so
  // `dist/adapter-kit.js` and `dist/eql/v3/index.js` share one chunk but
  // `dist/wasm-inline.js` (a separate esbuild run) does not; and CJS does not
  // split at all, so `adapter-kit.cjs`, `eql/v3/index.cjs` and
  // `encryption/v3.cjs` each define their own. Whenever the adapter and the
  // schema resolved different copies — every CJS consumer, and ESM consumers
  // authoring from wasm-inline — `builder instanceof EncryptedV3Column` failed
  // for EVERY column, leaving `v3Columns` empty. The filter collector then
  // skipped every term and the RAW PLAINTEXT operand went into the PostgREST
  // query string, while `::jsonb` casts and decryption kept working.
  //
  // These two assert the MECHANISM (`v3Columns` is populated / not
  // over-populated). The HARM — what PostgREST actually receives — is asserted
  // in `supabase-v3-wire.test.ts` by Step 2, because a check that merely
  // probed `getName` would satisfy the two below.
  it('accepts a builder that merely has the v3 column surface', () => {
    const table = wasmAuthoredV3Table('users', ['email'])

    const columns = new ColumnMap('users', table as never, null)

    expect(columns.isEncryptedV3Column('email')).toBe(true)
    expect(columns.encryptedColumnNames).toContain('email')
  })

  it('throws on a builder missing the v3 column surface', () => {
    // v2 columns have `build()` and `getName()` (`EncryptedColumn`,
    // `packages/stack/src/schema/index.ts:442,449`) but neither `getEqlType()`
    // nor `getQueryCapabilities()` (`eql/v3/columns.ts:445,450`). Four probes,
    // not two, is what keeps the predicate honest.
    //
    // `columnBuilders` on an `AnyV3Table` must hold ONLY encrypted v3 columns,
    // so a builder that fails the probe is malformed input. Silently skipping it
    // is not a safe default: the column would drop out of `v3Columns` and its
    // filter operands would go to PostgREST as PLAINTEXT. Fail closed at
    // construction instead.
    const v2 = { getName: () => 'email', build: () => ({}) }
    const table = {
      tableName: 'users',
      columnBuilders: { email: v2 },
      buildColumnKeyMap: () => ({ email: 'email' }),
      build: () => ({ tableName: 'users', columns: {} }),
    }

    // Pin the SPECIFIC message, not just the `[supabase v3]` prefix: 40 errors
    // across this package share that prefix, three of them thrown by `ColumnMap`
    // itself. A prefix-only matcher stays green whenever a DIFFERENT one of
    // those fires first — measured: with `assertNoPropertyDbNameCollision`
    // throwing unconditionally, so the fail-closed probe below is never
    // reached, this test still passed. It could not tell which error it caught.
    // (Deleting the probe outright does turn it red — construction then
    // succeeds and nothing throws. It is the bypass, not the deletion, that the
    // loose matcher was blind to.)
    expect(() => new ColumnMap('users', table as never, null)).toThrow(
      /\[supabase v3\]: column "email" on table "users" is not a recognised EQL v3 column builder/,
    )
  })

  it('throws a diagnosis, not a raw TypeError, on a whole v2 table', () => {
    // A v2 `EncryptedTable` is structurally identical to a v3 one at the table
    // level — same `tableName`, same `columnBuilders`. The only discriminator
    // is `buildColumnKeyMap()`, which the constructor calls UNGUARDED as its
    // first statement, so a v2 table died with `table.buildColumnKeyMap is not
    // a function` — naming an internal method, not the version mismatch that
    // caused it.
    //
    // The column-level probe above cannot catch this: it runs later, and by
    // then the constructor has already crashed.
    const v2Table = {
      tableName: 'users',
      columnBuilders: { email: { getName: () => 'email', build: () => ({}) } },
      build: () => ({ tableName: 'users', columns: {} }),
    }

    expect(() => new ColumnMap('users', v2Table as never, null)).toThrow(
      /\[supabase v3\]: table "users" is an EQL v2 table/,
    )
  })
})

describe('every types.* domain satisfies the structural v3 probe', () => {
  // Stated through the public consequence rather than against the predicate:
  // whatever the catalog grows to, ColumnMap must see the column as encrypted.
  // A domain whose builder lost one of the four methods would be silently
  // treated as PLAINTEXT — the PF2 failure again, from a different direction.
  // Enumerated, not hardcoded (40 domains today), so a new one is covered the
  // day it is added. The predicate's own shape is pinned separately, one probe
  // at a time, in `column-map-predicate.test.ts`.
  it('recognises a column built by any factory in the catalog', () => {
    // Deterministic iteration over the WHOLE catalog, not a probabilistic
    // sample: the guarantee this pins is "every domain", so every domain must
    // actually run. `fc.constantFrom` would leave that to chance across its
    // default run count.
    for (const domain of Object.keys(types) as (keyof typeof types)[]) {
      const table = encryptedTable('t', { c: types[domain]('c') })

      const columns = new ColumnMap('t', table as never, null)

      expect(columns.isEncryptedV3Column('c')).toBe(true)
    }
  })
})
