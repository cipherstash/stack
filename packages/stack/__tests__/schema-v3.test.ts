import { describe, expect, it } from 'vitest'
import { resolveIndexType } from '@/encryption/helpers/infer-index-type'
import { encryptConfigSchema, encryptedColumn } from '@/schema'
import {
  buildEncryptConfig,
  EncryptedTable,
  EncryptedTextSearchColumn,
  encryptedDateColumn,
  encryptedDateOrdColumn,
  encryptedInt4OrdColumn,
  encryptedTable,
  encryptedTextMatchColumn,
  encryptedTextOrdColumn,
  encryptedTextSearchColumn,
  encryptedTimestamptzColumn,
} from '@/schema/v3'
import { type DomainSpec, typedEntries, V3_MATRIX } from './v3-matrix/catalog'

describe('eql_v3 text_search column', () => {
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

// The scalar query types a caller can request against a v3 domain. `searchableJson`
// / steVec are JSONB-only and out of scope for the scalar matrix.
const SCALAR_QUERY_TYPES = [
  'equality',
  'orderAndRange',
  'freeTextSearch',
] as const

// The ground-truth for whether `resolveIndexType` accepts a (domain, queryType)
// pair: does the domain carry the index that query resolves to? Derived from the
// catalog's `indexes` data, AMENDED for the equality-via-ORE rule — an
// order-capable column answers equality via its `ore` index, not `unique`. This
// mirrors `resolveIndexType`'s real logic, so it needs no live FFI.
function queryTypeAllowed(
  indexes: DomainSpec['indexes'],
  queryType: (typeof SCALAR_QUERY_TYPES)[number],
): boolean {
  const idx = indexes ?? {}
  if (queryType === 'equality') return Boolean(idx.unique || idx.ore)
  if (queryType === 'orderAndRange') return Boolean(idx.ore)
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
    const matchOnly = encryptedTextMatchColumn('body')
    expect(() => resolveIndexType(matchOnly, 'equality')).toThrow(
      /Index type "unique" is not configured/,
    )
    expect(() => resolveIndexType(matchOnly, 'orderAndRange')).toThrow(
      /Index type "ore" is not configured/,
    )
  })
})

describe('eql_v3 equality via ORE on order-capable columns (regression)', () => {
  // The capability contract documents equality as answerable "via `ob`", so an
  // order-capable column resolves equality to its `ore` index (same term as
  // orderAndRange, distinguished by the SQL `=` operator) instead of throwing on
  // the absent `unique` index. One domain per plaintext axis.
  it.each([
    ['int4_ord', encryptedInt4OrdColumn],
    ['date_ord', encryptedDateOrdColumn],
    ['text_ord', encryptedTextOrdColumn],
  ] as const)('%s resolves equality to the ore index', (_name, builder) => {
    expect(resolveIndexType(builder('value'), 'equality')).toEqual({
      indexType: 'ore',
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
