/**
 * Pin the shape of {@link deriveStackSchemas} against the full set of
 * cipherstash codecs and search-mode flags. Uses synthesised contract
 * JSON fragments so the test is hermetic — no dependency on the
 * example app's contract.json or on the framework's contract emitter.
 */

import { describe, expect, it } from 'vitest'

import {
  CIPHERSTASH_BIGINT_CODEC_ID,
  CIPHERSTASH_BOOLEAN_CODEC_ID,
  CIPHERSTASH_DATE_CODEC_ID,
  CIPHERSTASH_DOUBLE_CODEC_ID,
  CIPHERSTASH_JSON_CODEC_ID,
  CIPHERSTASH_STRING_CODEC_ID,
} from '../src/extension-metadata/constants'
import { deriveStackSchemas } from '../src/stack/derive-schemas'

function makeContract(
  tables: Record<
    string,
    Record<
      string,
      { codecId: string; typeParams?: Record<string, boolean> | null }
    >
  >,
) {
  return {
    storage: {
      namespaces: {
        __unbound__: {
          entries: {
            table: Object.fromEntries(
              Object.entries(tables).map(([name, cols]) => [
                name,
                {
                  columns: cols as Record<
                    string,
                    {
                      codecId: string
                      typeParams?: Record<string, unknown> | null
                    }
                  >,
                },
              ]),
            ),
          },
        },
      },
    },
  }
}

describe('deriveStackSchemas', () => {
  it('returns an empty array when contract has no storage tables', () => {
    expect(deriveStackSchemas({})).toEqual([])
    expect(deriveStackSchemas({ storage: {} })).toEqual([])
    expect(deriveStackSchemas({ storage: { namespaces: {} } })).toEqual([])
    expect(
      deriveStackSchemas({
        storage: { namespaces: { __unbound__: { entries: { table: {} } } } },
      }),
    ).toEqual([])
  })

  it('skips tables with no cipherstash columns', () => {
    const contract = makeContract({
      users: {
        id: { codecId: 'pg/text@1', typeParams: null },
      },
    })
    expect(deriveStackSchemas(contract)).toEqual([])
  })

  it('derives one EncryptedTable per table that has cipherstash columns', () => {
    const contract = makeContract({
      users: {
        id: { codecId: 'pg/text@1', typeParams: null },
        email: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: { equality: true },
        },
      },
      audit_log: {
        message: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: { equality: true },
        },
      },
    })
    const schemas = deriveStackSchemas(contract)
    expect(schemas).toHaveLength(2)
    expect(schemas.map((t) => t.tableName).sort()).toEqual([
      'audit_log',
      'users',
    ])
  })

  it('maps each cipherstash codec id to the correct dataType', () => {
    const contract = makeContract({
      t: {
        s: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: { equality: true },
        },
        d: {
          codecId: CIPHERSTASH_DOUBLE_CODEC_ID,
          typeParams: { equality: true },
        },
        b: {
          codecId: CIPHERSTASH_BIGINT_CODEC_ID,
          typeParams: { equality: true },
        },
        dt: {
          codecId: CIPHERSTASH_DATE_CODEC_ID,
          typeParams: { equality: true },
        },
        bo: {
          codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
          typeParams: { equality: true },
        },
        j: {
          codecId: CIPHERSTASH_JSON_CODEC_ID,
          typeParams: { searchableJson: true },
        },
      },
    })
    const [t] = deriveStackSchemas(contract)
    const built = t!.build()
    // `build().cast_as` returns SDK-facing aliases ('string', 'number', 'bigint', ...);
    // the EQL `cast_as` lower-form ('text', 'double', 'big_int', ...) is derived
    // internally by the stack client at encrypt time.
    expect(built.columns.s?.cast_as).toBe('string')
    expect(built.columns.d?.cast_as).toBe('number')
    expect(built.columns.b?.cast_as).toBe('bigint')
    expect(built.columns.dt?.cast_as).toBe('date')
    expect(built.columns.bo?.cast_as).toBe('boolean')
    expect(built.columns.j?.cast_as).toBe('json')
  })

  it('installs index methods for each true-valued search-mode flag', () => {
    const contract = makeContract({
      users: {
        email: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: {
            equality: true,
            freeTextSearch: true,
            orderAndRange: true,
          },
        },
        bio: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: {
            equality: false,
            freeTextSearch: true,
            orderAndRange: false,
          },
        },
        preferences: {
          codecId: CIPHERSTASH_JSON_CODEC_ID,
          typeParams: { searchableJson: true },
        },
      },
    })
    const [users] = deriveStackSchemas(contract)
    const built = users!.build()

    // email — all three indices
    expect(Object.keys(built.columns.email?.indexes ?? {})).toEqual(
      expect.arrayContaining(['unique', 'match', 'ore']),
    )

    // bio — only match (freeTextSearch); equality/orderAndRange false → no unique/ore
    expect(built.columns.bio?.indexes.unique).toBeUndefined()
    expect(built.columns.bio?.indexes.match).toBeDefined()
    expect(built.columns.bio?.indexes.ore).toBeUndefined()

    // preferences — ste_vec only
    expect(built.columns.preferences?.indexes.ste_vec).toBeDefined()
  })

  it('skips false-valued flags (treats absent and false as equivalent)', () => {
    const contract = makeContract({
      t: {
        c: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          // explicit false on every flag should produce a column with no indices
          typeParams: {
            equality: false,
            freeTextSearch: false,
            orderAndRange: false,
          },
        },
      },
    })
    const [t] = deriveStackSchemas(contract)
    const built = t!.build()
    expect(built.columns.c?.indexes).toEqual({})
  })

  it('throws on an unrecognised typeParams flag (catches framework-vs-SDK vocabulary drift)', () => {
    const contract = makeContract({
      t: {
        c: {
          codecId: CIPHERSTASH_STRING_CODEC_ID,
          typeParams: { equality: true, futureFlag: true } as Record<
            string,
            boolean
          >,
        },
      },
    })
    expect(() => deriveStackSchemas(contract)).toThrow(/futureFlag/)
  })

  it('uses the physical column name (the storage IR key, post-@map)', () => {
    // contract.json's `storage.tables.<table>.columns.<col>` keys are
    // already the physical post-@map names. The derivation must keep
    // those names verbatim, not the PSL field names.
    const contract = makeContract({
      users: {
        emailverified: {
          codecId: CIPHERSTASH_BOOLEAN_CODEC_ID,
          typeParams: { equality: true },
        },
      },
    })
    const [users] = deriveStackSchemas(contract)
    expect(users!.build().columns.emailverified).toBeDefined()
  })
})
