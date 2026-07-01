import { describe, expect, it } from 'vitest'
import { resolveIndexType } from '@/encryption/helpers/infer-index-type'
import { encryptConfigSchema, encryptedColumn } from '@/schema'
import {
  buildEncryptConfig,
  EncryptedBoolColumn,
  EncryptedDateColumn,
  EncryptedDateEqColumn,
  EncryptedDateOrdColumn,
  EncryptedDateOrdOreColumn,
  EncryptedFloat4Column,
  EncryptedFloat4EqColumn,
  EncryptedFloat4OrdColumn,
  EncryptedFloat4OrdOreColumn,
  EncryptedFloat8Column,
  EncryptedFloat8EqColumn,
  EncryptedFloat8OrdColumn,
  EncryptedFloat8OrdOreColumn,
  EncryptedInt2Column,
  EncryptedInt2EqColumn,
  EncryptedInt2OrdColumn,
  EncryptedInt2OrdOreColumn,
  EncryptedInt4Column,
  EncryptedInt4EqColumn,
  EncryptedInt4OrdColumn,
  EncryptedInt4OrdOreColumn,
  EncryptedNumericColumn,
  EncryptedNumericEqColumn,
  EncryptedNumericOrdColumn,
  EncryptedNumericOrdOreColumn,
  EncryptedTable,
  EncryptedTextColumn,
  EncryptedTextEqColumn,
  EncryptedTextMatchColumn,
  EncryptedTextOrdColumn,
  EncryptedTextOrdOreColumn,
  EncryptedTextSearchColumn,
  EncryptedTimestamptzColumn,
  EncryptedTimestamptzEqColumn,
  EncryptedTimestamptzOrdColumn,
  EncryptedTimestamptzOrdOreColumn,
  encryptedBoolColumn,
  encryptedDateColumn,
  encryptedDateEqColumn,
  encryptedDateOrdColumn,
  encryptedDateOrdOreColumn,
  encryptedFloat4Column,
  encryptedFloat4EqColumn,
  encryptedFloat4OrdColumn,
  encryptedFloat4OrdOreColumn,
  encryptedFloat8Column,
  encryptedFloat8EqColumn,
  encryptedFloat8OrdColumn,
  encryptedFloat8OrdOreColumn,
  encryptedInt2Column,
  encryptedInt2EqColumn,
  encryptedInt2OrdColumn,
  encryptedInt2OrdOreColumn,
  encryptedInt4Column,
  encryptedInt4EqColumn,
  encryptedInt4OrdColumn,
  encryptedInt4OrdOreColumn,
  encryptedNumericColumn,
  encryptedNumericEqColumn,
  encryptedNumericOrdColumn,
  encryptedNumericOrdOreColumn,
  encryptedTable,
  encryptedTextColumn,
  encryptedTextEqColumn,
  encryptedTextMatchColumn,
  encryptedTextOrdColumn,
  encryptedTextOrdOreColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzColumn,
  encryptedTimestamptzEqColumn,
  encryptedTimestamptzOrdColumn,
  encryptedTimestamptzOrdOreColumn,
} from '@/schema/v3'

const domainCases = [
  [
    'eql_v3.int4',
    encryptedInt4Column,
    EncryptedInt4Column,
    'number',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.int4_eq',
    encryptedInt4EqColumn,
    EncryptedInt4EqColumn,
    'number',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.int4_ord_ore',
    encryptedInt4OrdOreColumn,
    EncryptedInt4OrdOreColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.int4_ord',
    encryptedInt4OrdColumn,
    EncryptedInt4OrdColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.int2',
    encryptedInt2Column,
    EncryptedInt2Column,
    'number',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.int2_eq',
    encryptedInt2EqColumn,
    EncryptedInt2EqColumn,
    'number',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.int2_ord_ore',
    encryptedInt2OrdOreColumn,
    EncryptedInt2OrdOreColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.int2_ord',
    encryptedInt2OrdColumn,
    EncryptedInt2OrdColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.date',
    encryptedDateColumn,
    EncryptedDateColumn,
    'date',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.date_eq',
    encryptedDateEqColumn,
    EncryptedDateEqColumn,
    'date',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.date_ord_ore',
    encryptedDateOrdOreColumn,
    EncryptedDateOrdOreColumn,
    'date',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.date_ord',
    encryptedDateOrdColumn,
    EncryptedDateOrdColumn,
    'date',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.timestamptz',
    encryptedTimestamptzColumn,
    EncryptedTimestamptzColumn,
    'date',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.timestamptz_eq',
    encryptedTimestamptzEqColumn,
    EncryptedTimestamptzEqColumn,
    'date',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.timestamptz_ord_ore',
    encryptedTimestamptzOrdOreColumn,
    EncryptedTimestamptzOrdOreColumn,
    'date',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.timestamptz_ord',
    encryptedTimestamptzOrdColumn,
    EncryptedTimestamptzOrdColumn,
    'date',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.numeric',
    encryptedNumericColumn,
    EncryptedNumericColumn,
    'number',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.numeric_eq',
    encryptedNumericEqColumn,
    EncryptedNumericEqColumn,
    'number',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.numeric_ord_ore',
    encryptedNumericOrdOreColumn,
    EncryptedNumericOrdOreColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.numeric_ord',
    encryptedNumericOrdColumn,
    EncryptedNumericOrdColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.text',
    encryptedTextColumn,
    EncryptedTextColumn,
    'string',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.text_eq',
    encryptedTextEqColumn,
    EncryptedTextEqColumn,
    'string',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.text_match',
    encryptedTextMatchColumn,
    EncryptedTextMatchColumn,
    'string',
    {
      match: {
        tokenizer: { kind: 'ngram', token_length: 3 },
        token_filters: [{ kind: 'downcase' }],
        k: 6,
        m: 2048,
        include_original: true,
      },
    },
    { equality: false, orderAndRange: false, freeTextSearch: true },
  ],
  [
    'eql_v3.text_ord_ore',
    encryptedTextOrdOreColumn,
    EncryptedTextOrdOreColumn,
    'string',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.text_ord',
    encryptedTextOrdColumn,
    EncryptedTextOrdColumn,
    'string',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.bool',
    encryptedBoolColumn,
    EncryptedBoolColumn,
    'boolean',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.float4',
    encryptedFloat4Column,
    EncryptedFloat4Column,
    'number',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.float4_eq',
    encryptedFloat4EqColumn,
    EncryptedFloat4EqColumn,
    'number',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.float4_ord_ore',
    encryptedFloat4OrdOreColumn,
    EncryptedFloat4OrdOreColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.float4_ord',
    encryptedFloat4OrdColumn,
    EncryptedFloat4OrdColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.float8',
    encryptedFloat8Column,
    EncryptedFloat8Column,
    'number',
    {},
    { equality: false, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.float8_eq',
    encryptedFloat8EqColumn,
    EncryptedFloat8EqColumn,
    'number',
    { unique: { token_filters: [] } },
    { equality: true, orderAndRange: false, freeTextSearch: false },
  ],
  [
    'eql_v3.float8_ord_ore',
    encryptedFloat8OrdOreColumn,
    EncryptedFloat8OrdOreColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
  [
    'eql_v3.float8_ord',
    encryptedFloat8OrdColumn,
    EncryptedFloat8OrdColumn,
    'number',
    { ore: {} },
    { equality: true, orderAndRange: true, freeTextSearch: false },
  ],
] as const

describe('eql_v3 concrete domain columns', () => {
  it.each(
    domainCases,
  )('%s builder exposes name, config, type, and capabilities', (eqlType, factory, Klass, castAs, indexes, capabilities) => {
    const col = factory('value')
    expect(col).toBeInstanceOf(Klass)
    expect(col.getName()).toBe('value')
    expect(col.getEqlType()).toBe(eqlType)
    expect(col.getQueryCapabilities()).toStrictEqual(capabilities)
    expect(col.isQueryable()).toBe(Object.values(capabilities).some(Boolean))
    expect(col.build()).toStrictEqual({ cast_as: castAs, indexes })
    expect(col.build()).not.toHaveProperty('eqlType')
    expect(col.build()).not.toHaveProperty('queryCapabilities')
  })
})

describe('eql_v3 text_search column', () => {
  it('returns an EncryptedTextSearchColumn with the correct name', () => {
    const col = encryptedTextSearchColumn('email')
    expect(col).toBeInstanceOf(EncryptedTextSearchColumn)
    expect(col.getName()).toBe('email')
  })

  it('.build() emits the pinned default config (cast_as: string + all three indexes)', () => {
    const built = encryptedTextSearchColumn('email').build()
    // toStrictEqual (not toEqual) so a stray `undefined` key would fail.
    expect(built).toStrictEqual({
      cast_as: 'string',
      indexes: {
        unique: { token_filters: [] },
        ore: {},
        match: {
          tokenizer: { kind: 'ngram', token_length: 3 },
          token_filters: [{ kind: 'downcase' }],
          k: 6,
          m: 2048,
          include_original: true,
        },
      },
    })
  })

  it('LOAD-BEARING: default build() deep-equals the v2 equality+order+match column', () => {
    const v3 = encryptedTextSearchColumn('email').build()
    const v2 = encryptedColumn('email')
      .equality()
      .orderAndRange()
      .freeTextSearch()
      .build()
    // toStrictEqual: byte-identical, no extra/undefined keys on either side.
    expect(v3).toStrictEqual(v2)
  })

  it('.freeTextSearch(opts) overrides each provided key and keeps the rest as defaults', () => {
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({
        tokenizer: { kind: 'ngram', token_length: 4 },
        k: 8,
        m: 4096,
        include_original: false,
      })
      .build()
    expect(built.indexes.match).toEqual({
      tokenizer: { kind: 'ngram', token_length: 4 },
      // omitted -> default downcase filter retained
      token_filters: [{ kind: 'downcase' }],
      k: 8,
      m: 4096,
      include_original: false,
    })
  })

  it('.freeTextSearch({ token_filters: [] }) overrides the downcase default with an empty array', () => {
    // LOAD-BEARING: `[] ?? default` evaluates to `[]` (an empty array is not
    // nullish), so an explicit empty array must OVERRIDE the downcase default,
    // not fall back to it. Mirrors v2 (schema-builders.test.ts).
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ token_filters: [] })
      .build()
    expect(built.indexes.match.token_filters).toEqual([])
  })

  it('repeated .freeTextSearch() calls are last-call-wins-fully (each re-merges against defaults, not prior state)', () => {
    // Each call re-merges against a fresh defaultMatchOpts(), not the
    // accumulated matchOpts — so the second call resets k back to its default
    // of 6. This is intentional: it mirrors v2 exactly. Pinned here so a future
    // "merge against current state" change can't silently slip in.
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ k: 8 })
      .freeTextSearch({ m: 4096 })
      .build()
    expect(built.indexes.match.k).toBe(6)
    expect(built.indexes.match.m).toBe(4096)
  })

  it('.freeTextSearch() is tuning-only: unique and ore indexes stay present', () => {
    const built = encryptedTextSearchColumn('email')
      .freeTextSearch({ k: 8 })
      .build()
    expect(built.indexes.unique).toEqual({ token_filters: [] })
    expect(built.indexes.ore).toEqual({})
  })

  it('getEqlType() returns the concrete domain name', () => {
    const col = encryptedTextSearchColumn('email')
    expect(col.getEqlType()).toBe('eql_v3.text_search')
  })

  it('exposes full query capabilities and is queryable', () => {
    expect(
      encryptedTextSearchColumn('email').getQueryCapabilities(),
    ).toStrictEqual({
      equality: true,
      orderAndRange: true,
      freeTextSearch: true,
    })
    expect(encryptedTextSearchColumn('email').isQueryable()).toBe(true)
  })

  it('eqlType metadata is absent from build() output', () => {
    const built = encryptedTextSearchColumn('email').build()
    expect(built).not.toHaveProperty('eqlType')
    expect(Object.keys(built).sort()).toEqual(['cast_as', 'indexes'])
  })

  it('built columns share no mutable state: mutating one build() output does not affect another', () => {
    // Guards against the shared-defaults aliasing bug: defaults come from a
    // per-instance factory and build() deep-clones the match block.
    const a = encryptedTextSearchColumn('a').build()
    const b = encryptedTextSearchColumn('b').build()

    // Mutate every nested level of a's match block.
    a.indexes.match.k = 999
    a.indexes.match.token_filters.push({ kind: 'downcase' })
    a.indexes.match.tokenizer = { kind: 'standard' }

    expect(b.indexes.match.k).toBe(6)
    expect(b.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
    expect(b.indexes.match.tokenizer).toEqual({
      kind: 'ngram',
      token_length: 3,
    })

    // A second build() of an independent column is also pristine.
    const c = encryptedTextSearchColumn('c').build()
    expect(c.indexes.match.k).toBe(6)
    expect(c.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })

  it('clones caller opts on freeTextSearch(): mutating them before build() does not leak', () => {
    // build() deep-clones at build time, but if freeTextSearch stored the
    // caller's nested tokenizer / token_filters by reference, a caller mutating
    // their own opts object between freeTextSearch(opts) and build() would leak
    // the mutation into the emitted config. freeTextSearch must clone on write.
    const opts = {
      tokenizer: { kind: 'ngram' as const, token_length: 3 },
      token_filters: [{ kind: 'downcase' as const }],
    }
    const col = encryptedTextSearchColumn('email').freeTextSearch(opts)

    // Mutate the caller's own opts AFTER freeTextSearch but BEFORE build().
    opts.tokenizer.token_length = 999
    opts.token_filters.push({ kind: 'downcase' as const })

    const built = col.build()
    expect(built.indexes.match.tokenizer).toEqual({
      kind: 'ngram',
      token_length: 3,
    })
    expect(built.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })
})

describe('eql_v3 encryptedTable', () => {
  it('creates a table exposing column builders as properties', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    expect(users).toBeInstanceOf(EncryptedTable)
    expect(users.tableName).toBe('users')
    expect(users.email).toBeInstanceOf(EncryptedTextSearchColumn)
  })

  it('table.email returns the same builder instance passed in', () => {
    const emailCol = encryptedTextSearchColumn('email')
    const users = encryptedTable('users', { email: emailCol })
    expect(users.email).toBe(emailCol)
  })

  it.each([
    'build',
    'tableName',
    'columnBuilders',
    '_columnType',
    // Inherited Object.prototype members: assigning these as own properties
    // would shadow the prototype method/accessor. Guard them too so the
    // table object stays well-behaved for reflection / serialization.
    'constructor',
    'toString',
    'valueOf',
    'hasOwnProperty',
  ])('throws when a column name (%s) collides with a reserved property', (reserved) => {
    expect(() =>
      encryptedTable('users', {
        [reserved]: encryptedTextSearchColumn(reserved),
      }),
    ).toThrow(/reserved EncryptedTable property/)
  })

  it('build() assembles { tableName, columns } with built column configs', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const built = users.build()
    expect(built.tableName).toBe('users')
    expect(built.columns).toStrictEqual({
      email: {
        cast_as: 'string',
        indexes: {
          unique: { token_filters: [] },
          ore: {},
          match: {
            tokenizer: { kind: 'ngram', token_length: 3 },
            token_filters: [{ kind: 'downcase' }],
            k: 6,
            m: 2048,
            include_original: true,
          },
        },
      },
    })
  })
})

describe('eql_v3 buildEncryptConfig', () => {
  it('produces a { v: 1, tables } config', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const config = buildEncryptConfig(users)
    expect(config.v).toBe(1)
    expect(config.tables).toHaveProperty('users')
    expect(config.tables.users).toHaveProperty('email')
  })

  it('emits a config that passes encryptConfigSchema.parse()', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const config = buildEncryptConfig(users)
    expect(() => encryptConfigSchema.parse(config)).not.toThrow()
  })

  it('supports multiple tables', () => {
    const users = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const posts = encryptedTable('posts', {
      body: encryptedTextSearchColumn('body'),
    })
    const config = buildEncryptConfig(users, posts)
    expect(Object.keys(config.tables).sort()).toEqual(['posts', 'users'])
  })

  it('keys columns by DB name (getName), not the JS property name', () => {
    // A camelCase JS key mapping to a snake_case DB column must register the
    // config under the DB name — `encrypt`/`decrypt` look columns up by
    // `column.getName()`, so keying by the JS property name makes the FFI
    // report "column not found in Encrypt config" at encrypt time.
    const users = encryptedTable('accounts', {
      createdOn: encryptedDateColumn('created_on'),
      lastSeen: encryptedTimestamptzColumn('last_seen'),
    })
    const config = buildEncryptConfig(users)
    expect(Object.keys(config.tables.accounts).sort()).toEqual([
      'created_on',
      'last_seen',
    ])
    expect(config.tables.accounts).not.toHaveProperty('createdOn')
    expect(config.tables.accounts).not.toHaveProperty('lastSeen')
  })

  it('buildColumnKeyMap maps JS property → DB column name', () => {
    // The model path matches user models by JS property but must address the
    // FFI/config by DB name. `build()` discards the property→name relationship
    // (it keys by DB name); `buildColumnKeyMap()` recovers it.
    const users = encryptedTable('accounts', {
      createdOn: encryptedDateColumn('created_on'),
      lastSeen: encryptedTimestamptzColumn('last_seen'),
      email: encryptedTextSearchColumn('email'),
    })
    expect(users.buildColumnKeyMap()).toEqual({
      createdOn: 'created_on',
      lastSeen: 'last_seen',
      email: 'email',
    })
  })

  it('throws when two tables share the same tableName (no silent drop)', () => {
    // v3-only additive guard: keying config.tables by name means a duplicate
    // would silently overwrite the earlier table. Fail loudly instead so the
    // footgun surfaces at build time. (v2 keeps its silent-overwrite behavior
    // unchanged — the no-v2-change constraint.)
    const a = encryptedTable('users', {
      email: encryptedTextSearchColumn('email'),
    })
    const b = encryptedTable('users', {
      name: encryptedTextSearchColumn('name'),
    })
    expect(() => buildEncryptConfig(a, b)).toThrow(
      /duplicate table name "users"/,
    )
  })
})

describe('eql_v3 query capability misuse', () => {
  it('throws when querying a storage-only v3 column at runtime', () => {
    const raw = encryptedTextColumn('raw')
    expect(() => resolveIndexType(raw as never)).toThrow(
      /no indexes configured/,
    )
  })

  it('throws when a query type is not configured on a queryable v3 column', () => {
    const matchOnly = encryptedTextMatchColumn('body')
    expect(() => resolveIndexType(matchOnly, 'equality')).toThrow(
      /Index type "unique" is not configured/,
    )
    expect(() => resolveIndexType(matchOnly, 'orderAndRange')).toThrow(
      /Index type "ore" is not configured/,
    )
  })
})
