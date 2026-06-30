import { describe, expect, it } from 'vitest'
import { encryptedColumn } from '@/schema'
import {
  EncryptedTextSearchColumn,
  encryptedTextSearchColumn,
} from '@/schema/v3'

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
    expect(b.indexes.match.tokenizer).toEqual({ kind: 'ngram', token_length: 3 })

    // A second build() of an independent column is also pristine.
    const c = encryptedTextSearchColumn('c').build()
    expect(c.indexes.match.k).toBe(6)
    expect(c.indexes.match.token_filters).toEqual([{ kind: 'downcase' }])
  })
})
