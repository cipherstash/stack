/**
 * `deriveStackSchemasV3` — contract.json → `@cipherstash/stack/eql/v3`
 * `encryptedTable`s. The v3 twin of `../derive-schemas.test.ts`, with
 * the v3-specific delta under test: the concrete factory is selected by
 * the column's `nativeType` (the `public.eql_v3_*` domain), never by
 * `typeParams` flags — v3 capabilities are intrinsic to the domain.
 */

import { describe, expect, it } from 'vitest'
import {
  deriveStackSchemasV3,
  v3ContractColumnEntries,
} from '../../src/v3/derive-schemas-v3'

// 0.14 contract shape: tables live under storage.namespaces.<ns>.entries.table
// (the Postgres default namespace is `public`).
function contract(
  columns: Record<
    string,
    { codecId: string; nativeType?: string; typeParams?: unknown }
  >,
  tableName = 'user',
) {
  return {
    storage: {
      namespaces: {
        public: { entries: { table: { [tableName]: { columns } } } },
      },
    },
  }
}

describe('deriveStackSchemasV3', () => {
  it('derives one v3 EncryptedTable, mapping public.eql_v3_* nativeType -> the concrete factory', () => {
    const [table] = deriveStackSchemasV3(
      contract({
        email: {
          codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
          nativeType: 'public.eql_v3_text_search',
        },
        score: {
          codecId: 'cipherstash/eql-v3/eql_v3_integer_ord@1',
          nativeType: 'public.eql_v3_integer_ord',
        },
        balance: {
          codecId: 'cipherstash/eql-v3/eql_v3_bigint_ord@1',
          nativeType: 'public.eql_v3_bigint_ord',
        },
      }),
    )
    expect(table).toBeDefined()
    const built = table?.build()
    expect(built?.tableName).toBe('user')
    // text_search = match + ope + unique (plain `_ord`/`_search` domains
    // are OPE-backed; only `*_ord_ore` carries `ore`).
    expect(Object.keys(built?.columns.email?.indexes ?? {}).sort()).toEqual([
      'match',
      'ope',
      'unique',
    ])
    expect(Object.keys(built?.columns.score?.indexes ?? {})).toEqual(['ope'])
    expect(built?.columns.email?.cast_as).toBe('string')
    expect(built?.columns.score?.cast_as).toBe('number')
    expect(built?.columns.balance?.cast_as).toBe('bigint')
  })

  it('derives a types.Json-backed column for public.eql_v3_json_search (ste_vec)', () => {
    const [table] = deriveStackSchemasV3(
      contract({
        payload: {
          codecId: 'cipherstash/eql-v3/eql_v3_json_search@1',
          nativeType: 'public.eql_v3_json_search',
        },
      }),
    )
    const built = table?.build()
    expect(built?.columns.payload?.cast_as).toBe('json')
    expect(Object.keys(built?.columns.payload?.indexes ?? {})).toEqual([
      'ste_vec',
    ])
  })

  it('preserves the exact domain on the derived column builders', () => {
    const [table] = deriveStackSchemasV3(
      contract({
        score: {
          codecId: 'cipherstash/eql-v3/eql_v3_integer_ord@1',
          nativeType: 'public.eql_v3_integer_ord',
        },
      }),
    )
    const builders = Object.values(table?.columnBuilders ?? {})
    expect(builders).toHaveLength(1)
    expect(builders[0]?.getEqlType()).toBe('public.eql_v3_integer_ord')
    expect(builders[0]?.getName()).toBe('score')
  })

  it('skips tables with no v3 columns (v2 codec ids are not v3 columns)', () => {
    expect(
      deriveStackSchemasV3(
        contract({
          x: {
            codecId: 'cipherstash/string@1',
            nativeType: 'eql_v2_encrypted',
          },
          y: { codecId: 'pg/text@1', nativeType: 'text' },
        }),
      ),
    ).toHaveLength(0)
  })

  it('merges tables across namespaces and skips non-v3 tables', () => {
    const tables = deriveStackSchemasV3({
      storage: {
        namespaces: {
          public: {
            entries: {
              table: {
                user: {
                  columns: {
                    email: {
                      codecId: 'cipherstash/eql-v3/eql_v3_text_eq@1',
                      nativeType: 'public.eql_v3_text_eq',
                    },
                  },
                },
                plain: {
                  columns: {
                    id: { codecId: 'pg/text@1', nativeType: 'text' },
                  },
                },
              },
            },
          },
        },
      },
    })
    expect(tables.map((t) => t.tableName)).toEqual(['user'])
  })

  it('throws when a v3 codec id has a nativeType with no eql/v3 factory', () => {
    expect(() =>
      deriveStackSchemasV3(
        contract({
          email: {
            codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
            nativeType: 'public.not_a_domain',
          },
        }),
      ),
    ).toThrow(/maps to no eql\/v3 factory/)
  })

  it('returns [] for a contract with no storage plane', () => {
    expect(deriveStackSchemasV3({})).toHaveLength(0)
  })
})

describe('v3ContractColumnEntries', () => {
  it('yields every column with its table, name, codecId, and nativeType', () => {
    const entries = v3ContractColumnEntries(
      contract({
        email: {
          codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
          nativeType: 'public.eql_v3_text_search',
        },
        id: { codecId: 'pg/text@1', nativeType: 'text' },
      }),
    )
    expect(entries).toHaveLength(2)
    expect(entries).toContainEqual({
      tableName: 'user',
      columnName: 'email',
      codecId: 'cipherstash/eql-v3/eql_v3_text_search@1',
      nativeType: 'public.eql_v3_text_search',
    })
  })
})
