import { describe, expect, it } from 'vitest'
import { resolveIndexType } from '@/encryption/helpers/infer-index-type'
import {
  buildEncryptConfig,
  EncryptedTable,
  EncryptedTextSearchColumn,
  encryptedTable,
  types,
} from '@/eql/v3'
import { encryptConfigSchema, encryptedColumn } from '@/schema'
import { type DomainSpec, typedEntries, V3_MATRIX } from './v3-matrix/catalog'

describe('eql_v3 text_search column', () => {
  it('LOAD-BEARING: default build() matches the v2 equality+order+match column modulo the ordering index', () => {
    // eql-3.0.0 pins text_search's ordering to CLLW-OPE (`ope`/`op` term); the
    // v2 fluent builder keeps block-ORE (`ore`/`ob`) — its wire format must not
    // change. Everything else (unique, match, cast_as) stays byte-identical.
    const v3 = types.TextSearch('email').build()
    const v2 = encryptedColumn('email')
      .equality()
      .orderAndRange()
      .freeTextSearch()
      .build()
    expect(v3.indexes.ope).toEqual({})
    expect(v3.indexes.ore).toBeUndefined()
    expect(v2.indexes.ore).toEqual({})
    expect(v2.indexes.ope).toBeUndefined()
    const { ope: _v3Ord, ...v3Rest } = v3.indexes
    const { ore: _v2Ord, ...v2Rest } = v2.indexes
    // toStrictEqual: byte-identical, no extra/undefined keys on either side.
    expect({ ...v3, indexes: v3Rest }).toStrictEqual({
      ...v2,
      indexes: v2Rest,
    })
  })

  it('default build() emits the unique, ope, and match indexes', () => {
    const built = types.TextSearch('email').build()
    expect(built.indexes.unique).toEqual({ token_filters: [] })
    expect(built.indexes.ope).toEqual({})
    expect(built.indexes.match).toEqual({
      tokenizer: { kind: 'ngram', token_length: 3 },
      token_filters: [{ kind: 'downcase' }],
      k: 6,
      m: 2048,
      include_original: true,
    })
  })

  it('built columns share no mutable state: mutating one build() output does not affect another', () => {
    // Guards against the shared-defaults aliasing bug: defaults come from a
    // per-instance factory and build() deep-clones the match block.
    const a = types.TextSearch('a').build()
    const b = types.TextSearch('b').build()

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
    const c = types.TextSearch('c').build()
    expect(c.indexes.match.k).toBe(6)
    expect(c.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })
})

describe('eql_v3 text_match column', () => {
  it('built columns share no mutable state: mutating one build() output does not affect another', () => {
    // Same aliasing guard as the text_search test above, but through the base
    // class indexesForCapabilities() match clone — text_match has no build()
    // override, so a regression there (e.g. sharing a defaultMatchOpts() result
    // across builds) would slip past the text_search-only test.
    const a = types.TextMatch('a').build()
    const b = types.TextMatch('b').build()

    a.indexes.match.k = 999
    a.indexes.match.token_filters.push({ kind: 'downcase' })
    a.indexes.match.tokenizer = { kind: 'standard' }

    expect(b.indexes.match.k).toBe(6)
    expect(b.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
    expect(b.indexes.match.tokenizer).toEqual({
      kind: 'ngram',
      token_length: 3,
    })

    // A fresh build() of an independent column is also pristine.
    const c = types.TextMatch('c').build()
    expect(c.indexes.match.k).toBe(6)
    expect(c.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })
})

describe('eql_v3 concrete type names', () => {
  it('preserves public factory names while exposing concrete Postgres domain names', () => {
    expect(types.Integer('n').getEqlType()).toBe('public.eql_v3_integer')
    expect(types.IntegerEq('n').getEqlType()).toBe('public.eql_v3_integer_eq')
    expect(types.IntegerOrdOre('n').getEqlType()).toBe(
      'public.eql_v3_integer_ord_ore',
    )
    expect(types.IntegerOrd('n').getEqlType()).toBe('public.eql_v3_integer_ord')

    expect(types.Smallint('n').getEqlType()).toBe('public.eql_v3_smallint')
    expect(types.SmallintEq('n').getEqlType()).toBe('public.eql_v3_smallint_eq')
    expect(types.SmallintOrdOre('n').getEqlType()).toBe(
      'public.eql_v3_smallint_ord_ore',
    )
    expect(types.SmallintOrd('n').getEqlType()).toBe(
      'public.eql_v3_smallint_ord',
    )

    expect(types.Bigint('n').getEqlType()).toBe('public.eql_v3_bigint')
    expect(types.BigintEq('n').getEqlType()).toBe('public.eql_v3_bigint_eq')
    expect(types.BigintOrdOre('n').getEqlType()).toBe(
      'public.eql_v3_bigint_ord_ore',
    )
    expect(types.BigintOrd('n').getEqlType()).toBe('public.eql_v3_bigint_ord')

    expect(types.Boolean('b').getEqlType()).toBe('public.eql_v3_boolean')
    expect(types.Real('n').getEqlType()).toBe('public.eql_v3_real')
    expect(types.RealEq('n').getEqlType()).toBe('public.eql_v3_real_eq')
    expect(types.RealOrdOre('n').getEqlType()).toBe(
      'public.eql_v3_real_ord_ore',
    )
    expect(types.RealOrd('n').getEqlType()).toBe('public.eql_v3_real_ord')
    expect(types.Double('n').getEqlType()).toBe('public.eql_v3_double')
    expect(types.DoubleEq('n').getEqlType()).toBe('public.eql_v3_double_eq')
    expect(types.DoubleOrdOre('n').getEqlType()).toBe(
      'public.eql_v3_double_ord_ore',
    )
    expect(types.DoubleOrd('n').getEqlType()).toBe('public.eql_v3_double_ord')
  })
})

describe('eql_v3 encryptedTable', () => {
  it('creates a table exposing column builders as properties', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    expect(users).toBeInstanceOf(EncryptedTable)
    expect(users.tableName).toBe('users')
    expect(users.email).toBeInstanceOf(EncryptedTextSearchColumn)
  })

  it('table.email returns the same builder instance passed in', () => {
    const emailCol = types.TextSearch('email')
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
        [reserved]: types.TextSearch(reserved),
      }),
    ).toThrow(/reserved EncryptedTable property/)
  })

  it('build() assembles { tableName, columns } with built column configs', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const built = users.build()
    expect(built.tableName).toBe('users')
    // Spread to a plain object: `columns` is null-prototype (a DB column named
    // `__proto__` must land as an own key), and `toStrictEqual` compares
    // prototypes. The contract under test is the column configs, not the
    // prototype — which `supabase-schema-builder.test.ts` pins directly.
    expect({ ...built.columns }).toStrictEqual({
      email: {
        cast_as: 'string',
        indexes: {
          unique: { token_filters: [] },
          ope: {},
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

  it('build() throws when two columns resolve to the same DB name (no silent overwrite)', () => {
    // Columns are keyed in the built config by DB name (`getName()`), so two JS
    // properties whose builders resolve to the same name would silently
    // overwrite — the later one wins and the first column's config is lost.
    // Fail loudly, matching the reserved-key and duplicate-tableName guards.
    const users = encryptedTable('users', {
      email: types.TextEq('contact'),
      contactEmail: types.TextMatch('contact'),
    })
    expect(() => users.build()).toThrow(/duplicate column name "contact"/)
  })

  it('build() surfaces the duplicate DB name through buildEncryptConfig', () => {
    const users = encryptedTable('users', {
      email: types.TextEq('contact'),
      contactEmail: types.TextMatch('contact'),
    })
    expect(() => buildEncryptConfig(users)).toThrow(
      /duplicate column name "contact"/,
    )
  })
})

describe('eql_v3 buildEncryptConfig', () => {
  it('zero tables yields an empty config (client-boundary Encryption() still rejects it)', () => {
    expect(buildEncryptConfig()).toStrictEqual({ v: 1, tables: {} })
  })

  it('produces a { v: 1, tables } config', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const config = buildEncryptConfig(users)
    expect(config.v).toBe(1)
    expect(config.tables).toHaveProperty('users')
    expect(config.tables.users).toHaveProperty('email')
  })

  it('emits a config that passes encryptConfigSchema.parse()', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const config = buildEncryptConfig(users)
    expect(() => encryptConfigSchema.parse(config)).not.toThrow()
  })

  it('supports multiple tables', () => {
    const users = encryptedTable('users', {
      email: types.TextSearch('email'),
    })
    const posts = encryptedTable('posts', {
      body: types.TextSearch('body'),
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
      createdOn: types.Date('created_on'),
      lastSeen: types.Timestamp('last_seen'),
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
      createdOn: types.Date('created_on'),
      lastSeen: types.Timestamp('last_seen'),
      email: types.TextSearch('email'),
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
      email: types.TextSearch('email'),
    })
    const b = encryptedTable('users', {
      name: types.TextSearch('name'),
    })
    expect(() => buildEncryptConfig(a, b)).toThrow(
      /duplicate table name "users"/,
    )
  })
})

// The scalar query types a caller can request against a v3 domain. `searchableJson`
// / steVec are JSONB-only and out of scope for the scalar matrix.
const SCALAR_QUERY_TYPES = [
  'equality',
  'orderAndRange',
  'freeTextSearch',
] as const

// The ground-truth for whether `resolveIndexType` accepts a (domain, queryType)
// pair: does the domain carry the index that query resolves to? Derived from the
// catalog's `indexes` data, AMENDED for the equality-via-ordering rule — an
// order-capable column answers equality via its ordering index (`ope` on `_ord`
// domains, `ore` on `_ord_ore`), not `unique`. This mirrors
// `resolveIndexType`'s real logic, so it needs no live FFI.
function queryTypeAllowed(
  indexes: DomainSpec['indexes'],
  queryType: (typeof SCALAR_QUERY_TYPES)[number],
): boolean {
  const idx = indexes ?? {}
  if (queryType === 'equality') return Boolean(idx.unique || idx.ore || idx.ope)
  if (queryType === 'orderAndRange') return Boolean(idx.ore || idx.ope)
  return Boolean(idx.match) // freeTextSearch
}

describe('eql_v3 catalog-driven query capability sweep', () => {
  // The Rust harness's `blocker_combos` analog: attempt every scalar queryType
  // against every domain and assert the throw/allow outcome the domain's
  // configured indexes dictate. Supersedes the two hand-picked cases that used
  // to live here — they are now just two of the generated rows.
  it.each(
    typedEntries(V3_MATRIX).flatMap(([eqlType, spec]) =>
      SCALAR_QUERY_TYPES.map(
        (queryType) => [eqlType, spec, queryType] as const,
      ),
    ),
  )('%s + queryType=%s: gating matches configured indexes', (_eqlType, spec, queryType) => {
    const col = spec.builder('value')
    if (queryTypeAllowed(spec.indexes, queryType)) {
      expect(() => resolveIndexType(col as never, queryType)).not.toThrow()
    } else {
      // Broad message match: for a blocked equality the resolver reports the
      // missing `unique`; for orderAndRange/freeTextSearch the missing ore/match.
      expect(() => resolveIndexType(col as never, queryType)).toThrow(
        /not configured/,
      )
    }
  })

  it.each(
    typedEntries(V3_MATRIX).filter(
      ([, spec]) => Object.keys(spec.indexes ?? {}).length === 0,
    ),
  )('%s: querying a storage-only column with no queryType throws', (_eqlType, spec) => {
    expect(() => resolveIndexType(spec.builder('value') as never)).toThrow(
      /no indexes configured/,
    )
  })

  // Spot-check the exact messages for a queryable-but-misused column, so the
  // broad regex above doesn't let a message regression slip through.
  it('reports the specific missing index for a match-only column', () => {
    const matchOnly = types.TextMatch('body')
    expect(() => resolveIndexType(matchOnly, 'equality')).toThrow(
      /Index type "unique" is not configured/,
    )
    expect(() => resolveIndexType(matchOnly, 'orderAndRange')).toThrow(
      /Index type "ore" is not configured/,
    )
  })
})

describe('eql_v3 equality via the ordering index on order-capable columns (regression)', () => {
  // The capability contract documents equality as answerable via the ordering
  // term, so a numeric/date order-capable column (which has NO `hm`) resolves
  // equality to its ordering index (same term as orderAndRange, distinguished
  // by the SQL `=` operator) instead of throwing on the absent `unique` index.
  // `_ord` domains are OPE-backed (eql-3.0.0), `_ord_ore` keep block-ORE.
  // (Text order domains DO carry `hm` and resolve equality to `unique`
  // instead — see the text-order regression below.)
  // Keep these labels aligned with the checked-in EQL build; a mismatch here
  // means the stack package is out of sync with the underlying domain surface.
  it.each([
    ['IntegerOrd', types.IntegerOrd, 'ope'],
    ['date_ord', types.DateOrd, 'ope'],
    ['numeric_ord', types.NumericOrd, 'ope'],
    ['IntegerOrdOre', types.IntegerOrdOre, 'ore'],
  ] as const)('%s resolves equality to its ordering index (%s)', (_name, builder, ordering) => {
    expect(resolveIndexType(builder('value'), 'equality')).toEqual({
      indexType: ordering,
    })
  })

  it('preserves v2: an orderAndRange-only column still throws on equality (no-v2-change)', () => {
    // v2 EncryptedColumn has no getQueryCapabilities, so the equality-via-ORE
    // branch never fires for it — the equality-without-unique throw is unchanged.
    const v2OrderOnly = encryptedColumn('x').orderAndRange()
    expect(() => resolveIndexType(v2OrderOnly, 'equality')).toThrow(
      /Index type "unique" is not configured/,
    )
  })
})

describe('eql_v3 text order domains carry the hm (unique) index (regression)', () => {
  // The `public.eql_v3_text_ord` and `public.eql_v3_text_ord_ore` SQL domains require BOTH
  // `hm` (HMAC) and `ob` (ORE) in the stored ciphertext: text equality is
  // HMAC-based (their `eql_v3.eq_term` extracts `hm`), unlike numeric/date order
  // domains which answer equality via `ob` and need only ORE. So text order
  // columns must emit `unique` (hm) IN ADDITION to `ore` (ob), or a real INSERT
  // fails with `value for domain public.eql_v3_text_ord_ore violates check constraint`.
  it.each([
    [
      'text_ord_ore',
      types.TextOrdOre,
      { unique: { token_filters: [] }, ore: {} },
    ],
    ['text_ord', types.TextOrd, { unique: { token_filters: [] }, ope: {} }],
  ] as const)('%s emits both unique (hm) and its ordering index', (_name, builder, expected) => {
    expect(builder('c').build().indexes).toStrictEqual(expected)
  })

  it.each([
    ['IntegerOrdOre', types.IntegerOrdOre, { ore: {} }],
    ['IntegerOrd', types.IntegerOrd, { ope: {} }],
    ['date_ord_ore', types.DateOrdOre, { ore: {} }],
    ['numeric_ord', types.NumericOrd, { ope: {} }],
  ] as const)('%s (numeric/date order) emits its ordering index only — no unique', (_name, builder, expected) => {
    expect(builder('c').build().indexes).toStrictEqual(expected)
  })

  // With `unique` present, text order equality resolves to the hm index (not
  // ORE): `resolvesEqualityViaOre` only fires when `unique` is ABSENT.
  it.each([
    ['text_ord_ore', types.TextOrdOre],
    ['text_ord', types.TextOrd],
  ] as const)('%s resolves equality to the unique (hm) index', (_name, builder) => {
    expect(resolveIndexType(builder('value'), 'equality')).toEqual({
      indexType: 'unique',
    })
  })
})

describe('eql_v3 timestamp domains emit cast_as "timestamp" (time-of-day preserved)', () => {
  // The FFI has a distinct `timestamp` cast (full date+time) separate from
  // `date` (calendar-date only). Every timestamp domain must emit
  // `cast_as: 'timestamp'` so the native layer keeps the time-of-day instead of
  // truncating to midnight (see schema-v3-client occurredAt round-trip).
  it.each([
    ['timestamp', types.Timestamp],
    ['timestamp_eq', types.TimestampEq],
    ['timestamp_ord_ore', types.TimestampOrdOre],
    ['timestamp_ord', types.TimestampOrd],
  ] as const)('%s emits cast_as "timestamp"', (_name, builder) => {
    expect(builder('c').build().cast_as).toBe('timestamp')
  })

  it('the plain date domain still emits cast_as "date"', () => {
    expect(types.Date('c').build().cast_as).toBe('date')
  })
})
