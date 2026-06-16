import { describe, expect, it } from 'vitest'
import { deriveStackSchemas } from '../../src/stack/derive-schemas'
import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'

function makeContract(tables: Record<string, Record<string, { codecId: string; typeParams?: unknown }>>) {
  return {
    storage: {
      tables: Object.fromEntries(
        Object.entries(tables).map(([name, cols]) => [name, { columns: cols }]),
      ),
    },
  } as never
}

describe('deriveStackSchemas (v3)', () => {
  it('maps each v3 string column to a string-cast column with exactly its one index', () => {
    const contract = makeContract({
      user_v3: {
        email: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index: 'equality' } },
        bio: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index: 'freeTextSearch' } },
        name: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index: 'orderAndRange' } },
      },
    })
    const schemas = deriveStackSchemas(contract)
    expect(schemas).toHaveLength(1)
    const built = schemas[0]!.build()

    // dataType is the string cast for every v3 text column.
    expect(built.columns.email?.cast_as).toBe('string')

    // equality → unique only; freeTextSearch → match only; orderAndRange → ore only.
    expect(Object.keys(built.columns.email?.indexes ?? {})).toEqual(['unique'])
    expect(Object.keys(built.columns.bio?.indexes ?? {})).toEqual(['match'])
    expect(Object.keys(built.columns.name?.indexes ?? {})).toEqual(['ore'])
  })

  it('throws on a v3 column with a missing/invalid index typeParam', () => {
    const missing = makeContract({ t: { c: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: {} } } })
    expect(() => deriveStackSchemas(missing)).toThrow(/index/)
    const bad = makeContract({ t: { c: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index: 'nope' } } } })
    expect(() => deriveStackSchemas(bad)).toThrow(/index/)
  })
})
