import { describe, expect, it } from 'vitest'
import { encryptConfigSchema } from '@/schema'

// The config `encryptConfigSchema.parse` returns is what protect-ffi indexes
// with, so its output is pinned here, field for field. An index option left
// out must stay out: protect-ffi applies its own default. zod 4 applies a
// `.default(x)` written inside `.optional()`, where zod 3 did not, so a
// default written that way would add fields to every config built before.
describe('encryptConfigSchema', () => {
  const parse = (tables: unknown) => encryptConfigSchema.parse({ v: 2, tables })

  it('leaves out the match and unique options a column leaves out', () => {
    expect(
      parse({
        users: {
          email: { cast_as: 'string', indexes: { match: {}, unique: {} } },
          name: {
            cast_as: 'string',
            indexes: { match: { tokenizer: { kind: 'standard' }, k: 8 } },
          },
        },
      }),
    ).toStrictEqual({
      v: 2,
      tables: {
        users: {
          email: { cast_as: 'string', indexes: { match: {}, unique: {} } },
          name: {
            cast_as: 'string',
            indexes: { match: { tokenizer: { kind: 'standard' }, k: 8 } },
          },
        },
      },
    })
  })

  it('keeps every option a column sets', () => {
    const match = {
      tokenizer: { kind: 'ngram', token_length: 3 },
      token_filters: [{ kind: 'downcase' }],
      k: 6,
      m: 2048,
      include_original: true,
    }
    expect(
      parse({ t: { c: { cast_as: 'string', indexes: { match } } } }),
    ).toStrictEqual({
      v: 2,
      tables: { t: { c: { cast_as: 'string', indexes: { match } } } },
    })
  })

  it('fills in a column cast_as and indexes, and a config with no tables', () => {
    expect(parse({ t: { a: {}, b: undefined } })).toStrictEqual({
      v: 2,
      tables: {
        t: {
          a: { cast_as: 'text', indexes: {} },
          b: { cast_as: 'text', indexes: {} },
        },
      },
    })
    expect(encryptConfigSchema.parse({ v: 2 })).toStrictEqual({
      v: 2,
      tables: {},
    })
  })

  it('refuses a config that does not fit', () => {
    for (const config of [
      {},
      { v: 'x' },
      { v: 2, tables: { t: { c: { cast_as: 'nope' } } } },
      { v: 2, tables: { t: { c: { indexes: { match: { k: 'x' } } } } } },
      { v: 2, tables: { t: { c: { indexes: { ste_vec: {} } } } } },
    ]) {
      expect(encryptConfigSchema.safeParse(config).success).toBe(false)
    }
  })
})
