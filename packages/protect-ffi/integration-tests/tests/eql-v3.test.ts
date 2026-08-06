import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type BigintEq,
  type BigintOrdOre,
  type DateOrdOre,
  type DoubleOrdOre,
  type EncryptConfig,
  type EncryptedV3,
  type EqlV3Boolean,
  type IntegerOrdOpe,
  type IntegerOrdOpeQuery,
  type IntegerOrdOre,
  type IntegerOrdOreQuery,
  type NumericOrdOre,
  type SmallintOrdOre,
  type SteVecDocument,
  type SteVecQuery,
  type TextEq,
  type TextEqQuery,
  type TextSearchOre,
  type TextSearchOreQuery,
  type TimestampOrdOre,
  decrypt,
  decryptBulk,
  decryptBulkFallible,
  encrypt,
  encryptBulk,
  encryptQuery,
  encryptQueryBulk,
  isEncrypted,
  newClient,
} from '@cipherstash/protect-ffi'
import { v3WireKeys } from './common'

// Every EQL v3 scalar family reachable from the JS cast_as vocabulary, plus
// boolean (storage-only) and json (SteVec). The eql_v3 domain each column must
// map onto is not documented here — it is asserted: the test cases below
// check every payload's exact top-level key set against the vendored
// eql_v3 domain type, so drift in the config -> domain selection fails the
// suite instead of silently invalidating a comment.
const v3Config: EncryptConfig = {
  v: 1,
  tables: {
    v3users: {
      email: {
        cast_as: 'text',
        indexes: { unique: {}, ore: {}, match: {} },
      },
      name: {
        cast_as: 'text',
        indexes: { unique: {} },
      },
      age: {
        cast_as: 'small_int',
        indexes: { ore: {} },
      },
      count: {
        cast_as: 'int',
        indexes: { ore: {} },
      },
      rank: {
        cast_as: 'int',
        indexes: { ope: {} },
      },
      score: {
        cast_as: 'bigint',
        indexes: { unique: {} },
      },
      big_score: {
        cast_as: 'bigint',
        indexes: { ore: {} },
      },
      weight: {
        cast_as: 'number',
        indexes: { ore: {} },
      },
      price: {
        cast_as: 'decimal',
        indexes: { ore: {} },
      },
      dob: {
        cast_as: 'date',
        indexes: { ore: {} },
      },
      created_at: {
        cast_as: 'timestamp',
        indexes: { ore: {} },
      },
      active: {
        cast_as: 'boolean',
      },
      profile: {
        cast_as: 'json',
        indexes: { ste_vec: { prefix: 'v3users/profile' } },
      },
    },
  },
}

function expectV3Scalar(payload: unknown): Record<string, unknown> {
  const p = payload as Record<string, unknown>
  expect(p.v).toBe(3)
  expect(p.k).toBeUndefined()
  expect(p.i).toBeTypeOf('object')
  expect(p.c).toBeTypeOf('string')
  return p
}

function expectV3SteVec(payload: unknown): SteVecDocument {
  const p = payload as Record<string, unknown>
  expect(p.v).toBe(3)
  // Unlike v3 scalars, SteVec documents keep the k form discriminator.
  expect(p.k).toBe('sv')
  expect(p.i).toBeTypeOf('object')
  expect(Array.isArray(p.sv)).toBe(true)
  return payload as SteVecDocument
}

describe('eql v3 scalar round-trips', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  type ScalarCase = {
    column: string
    plaintext: string | number | boolean | bigint
    /**
     * What decrypt returns when it differs from the input — bigint
     * columns ALWAYS decrypt to a JS bigint, even for number inputs
     * (breaking change: previously a number came back).
     */
    expected?: string | number | boolean | bigint
    /** the eql_v3 domain the config must select for this column */
    domain: string
    /**
     * Exact top-level wire keys. Built with {@link v3WireKeys} against the
     * vendored eql_v3 domain type, so the expectation itself is
     * compile-time-checked; the runtime assertion below then compares the
     * payload's key set with exact equality (no extra, no missing keys).
     */
    keys: readonly string[]
  }

  const cases: ScalarCase[] = [
    // text with unique + ore + match reaches the richest domain
    {
      column: 'email',
      plaintext: 'v3@example.com',
      domain: 'text_search_ore',
      keys: v3WireKeys<TextSearchOre>()('v', 'i', 'c', 'hm', 'ob', 'bf'),
    },
    // unique-only text carries hm only
    {
      column: 'name',
      plaintext: 'Ada',
      domain: 'text_eq',
      keys: v3WireKeys<TextEq>()('v', 'i', 'c', 'hm'),
    },
    // non-text _ord_ore domains carry ob only
    {
      column: 'age',
      plaintext: 42,
      domain: 'smallint_ord_ore',
      keys: v3WireKeys<SmallintOrdOre>()('v', 'i', 'c', 'ob'),
    },
    {
      column: 'count',
      plaintext: 123456,
      domain: 'integer_ord_ore',
      keys: v3WireKeys<IntegerOrdOre>()('v', 'i', 'c', 'ob'),
    },
    // ope maps onto the _ord_ope domains, carrying op (CLLW-OPE) — emitted
    // since cipherstash-client 0.38.1
    {
      column: 'rank',
      plaintext: 7,
      domain: 'integer_ord_ope',
      keys: v3WireKeys<IntegerOrdOpe>()('v', 'i', 'c', 'op'),
    },
    {
      column: 'score',
      plaintext: 9007199254740,
      expected: 9007199254740n,
      domain: 'bigint_eq',
      keys: v3WireKeys<BigintEq>()('v', 'i', 'c', 'hm'),
    },
    // bigint input beyond Number.MAX_SAFE_INTEGER: eq carries hm
    {
      column: 'score',
      plaintext: 2n ** 62n,
      domain: 'bigint_eq',
      keys: v3WireKeys<BigintEq>()('v', 'i', 'c', 'hm'),
    },
    // ore-indexed bigint carries ob only (no hm on non-text ord domains)
    {
      column: 'big_score',
      plaintext: 9223372036854775807n, // i64::MAX
      domain: 'bigint_ord_ore',
      keys: v3WireKeys<BigintOrdOre>()('v', 'i', 'c', 'ob'),
    },
    {
      column: 'weight',
      plaintext: 72.5,
      domain: 'double_ord_ore',
      keys: v3WireKeys<DoubleOrdOre>()('v', 'i', 'c', 'ob'),
    },
    {
      column: 'price',
      plaintext: 19.99,
      domain: 'numeric_ord_ore',
      keys: v3WireKeys<NumericOrdOre>()('v', 'i', 'c', 'ob'),
    },
    // boolean is storage-only: envelope keys and nothing else
    {
      column: 'active',
      plaintext: true,
      domain: 'boolean',
      keys: v3WireKeys<EqlV3Boolean>()('v', 'i', 'c'),
    },
  ]

  test.each(cases)(
    'round-trips $column as eql_v3.$domain',
    async ({ column, plaintext, expected, domain, keys }) => {
      const ciphertext = await encrypt(client, {
        plaintext,
        column,
        table: 'v3users',
      })

      const payload = expectV3Scalar(ciphertext)
      expect(
        Object.keys(payload).sort(),
        `the config must map ${column} onto eql_v3.${domain}`,
      ).toEqual(keys)

      const decrypted = await decrypt(client, { ciphertext })
      if (expected !== undefined) {
        expect(decrypted).toBe(expected)
      } else if (
        typeof plaintext === 'number' &&
        !Number.isInteger(plaintext)
      ) {
        // decimal decrypts to a string representation
        expect(Number(decrypted)).toBeCloseTo(plaintext)
      } else {
        expect(decrypted).toBe(plaintext)
      }
    },
  )

  test('round-trips a date column as eql_v3.date_ord_ore', async () => {
    const d = new Date('2024-03-01T00:00:00.000Z')
    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      column: 'dob',
      table: 'v3users',
    })

    expect(Object.keys(expectV3Scalar(ciphertext)).sort()).toEqual(
      v3WireKeys<DateOrdOre>()('v', 'i', 'c', 'ob'),
    )

    const decrypted = await decrypt(client, { ciphertext })
    expect(new Date(decrypted as string).toISOString().slice(0, 10)).toBe(
      '2024-03-01',
    )
  })

  test('round-trips a timestamp column as eql_v3.timestamp_ord_ore', async () => {
    const d = new Date('2024-03-01T12:34:56.000Z')
    const ciphertext = await encrypt(client, {
      plaintext: d.toISOString(),
      column: 'created_at',
      table: 'v3users',
    })

    expect(Object.keys(expectV3Scalar(ciphertext)).sort()).toEqual(
      v3WireKeys<TimestampOrdOre>()('v', 'i', 'c', 'ob'),
    )

    const decrypted = await decrypt(client, { ciphertext })
    expect(new Date(decrypted as string).toISOString()).toBe(d.toISOString())
  })

  test('match-indexed text emits bf as signed 16-bit numbers', async () => {
    const ciphertext = await encrypt(client, {
      plaintext: 'the quick brown fox jumps over the lazy dog',
      column: 'email',
      table: 'v3users',
    })

    const bf = expectV3Scalar(ciphertext).bf as number[]
    expect(Array.isArray(bf)).toBe(true)
    expect(bf.length).toBeGreaterThan(0)
    for (const bit of bf) {
      expect(typeof bit).toBe('number')
      expect(Number.isInteger(bit)).toBe(true)
      expect(bit).toBeGreaterThanOrEqual(-32768)
      expect(bit).toBeLessThanOrEqual(32767)
    }
  })

  test('encryptBulk returns v3 payloads and decryptBulk round-trips them', async () => {
    const ciphertexts = await encryptBulk(client, {
      plaintexts: [
        { plaintext: 'bulk@example.com', column: 'email', table: 'v3users' },
        { plaintext: 7, column: 'count', table: 'v3users' },
      ],
    })

    for (const ciphertext of ciphertexts) {
      expectV3Scalar(ciphertext)
    }

    const decrypted = await decryptBulk(client, {
      ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
    })
    expect(decrypted).toEqual(['bulk@example.com', 7])
  })

  test('decryptBulkFallible reports a bad payload without failing the batch', async () => {
    const good = await encrypt(client, {
      plaintext: 'fallible@example.com',
      column: 'email',
      table: 'v3users',
    })

    const results = await decryptBulkFallible(client, {
      ciphertexts: [
        { ciphertext: good },
        // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid payload
        { ciphertext: { random: 'data' } as any },
      ],
    })

    expect(results[0]).toEqual({ data: 'fallible@example.com' })
    expect(results[1]).toHaveProperty('error')
  })
})

describe('eql v3 ste_vec round-trip', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('encrypts json to a SteVecDocument and decrypts sv[0].c back', async () => {
    const profile = { role: 'admin', level: 3, tags: ['a', 'b'] }

    const ciphertext = await encrypt(client, {
      plaintext: profile,
      column: 'profile',
      table: 'v3users',
    })

    const doc = expectV3SteVec(ciphertext)
    expect(Object.keys(doc).sort()).toEqual(
      v3WireKeys<SteVecDocument>()('v', 'k', 'i', 'h', 'sv'),
    )
    expect(doc.h).toBeTypeOf('string')
    expect(doc.sv.length).toBeGreaterThan(0)
    for (const entry of doc.sv) {
      expect(entry.s).toBeTypeOf('string')
      expect(entry.c).toBeTypeOf('string')
      const term = entry as unknown as Record<string, unknown>
      expect(term.hm, 'exact equality is encoded in selectors').toBeUndefined()
      expect(
        'oc' in term && term.oc !== undefined,
        'EQL v3 rejects the legacy CLLW-ORE `oc` term',
      ).toBe(false)
    }

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toEqual(profile)
  })
})

describe('eql v3 query encryption', async () => {
  const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  /** Term-only operand: v3 envelope, no ciphertext, no form discriminator. */
  function expectV3QueryOperand(payload: unknown): Record<string, unknown> {
    const p = payload as Record<string, unknown>
    expect(p.v).toBe(3)
    expect(p.k).toBeUndefined()
    expect(p.i).toBeTypeOf('object')
    expect(p.c, 'query operands must not carry a ciphertext').toBeUndefined()
    return p
  }

  test('containment query returns the query_json needle', async () => {
    const result = (await encryptQuery(client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
    })) as SteVecQuery & Record<string, unknown>

    // The needle has no envelope and no per-entry ciphertexts.
    expect(result.v).toBeUndefined()
    expect(result.i).toBeUndefined()
    expect(result.k).toBeUndefined()
    expect(Array.isArray(result.sv)).toBe(true)
    for (const entry of result.sv) {
      expect(entry.s).toBeTypeOf('string')
      const e = entry as unknown as Record<string, unknown>
      expect(e.c).toBeUndefined()
      expect(e.hm).toBeUndefined()
      expect(e.oc).toBeUndefined()
    }
  })

  test('exact path/value query returns one selector-only needle entry', async () => {
    const result = (await encryptQuery(client, {
      plaintext: { path: '$.role', value: 'admin' },
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_value_selector',
    })) as SteVecQuery & Record<string, unknown>

    expect(result.sv).toHaveLength(1)
    expect(result.sv[0].s).toBeTypeOf('string')
    expect(result.sv[0].op).toBeUndefined()
  })

  test('containment query via default queryOp with an object also converts', async () => {
    const result = (await encryptQuery(client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
    })) as Record<string, unknown>

    expect(result.v).toBeUndefined()
    expect(Array.isArray(result.sv)).toBe(true)
  })

  type ScalarQueryCase = {
    column: string
    plaintext: string | number
    indexType: 'unique' | 'ore' | 'ope' | 'match'
    /** the query twin the operand must target: eql_v3.query_<domain> */
    domain: string
    /** exact top-level wire keys — the column DOMAIN's terms, no c */
    keys: readonly string[]
  }

  // The operand always carries ALL the column domain's terms, whichever
  // indexType was queried — the SQL operators pair each column domain only
  // with its same-name eql_v3.query_<name> twin, whose CHECK requires the
  // full term set.
  const scalarQueryCases: ScalarQueryCase[] = [
    {
      column: 'email',
      plaintext: 'v3@example.com',
      indexType: 'unique',
      domain: 'text_search_ore',
      keys: v3WireKeys<TextSearchOreQuery>()('v', 'i', 'hm', 'ob', 'bf'),
    },
    // match on the same column: identical operand — tracks the column
    // domain, not the queried index
    {
      column: 'email',
      plaintext: 'example',
      indexType: 'match',
      domain: 'text_search_ore',
      keys: v3WireKeys<TextSearchOreQuery>()('v', 'i', 'hm', 'ob', 'bf'),
    },
    {
      column: 'name',
      plaintext: 'Ada',
      indexType: 'unique',
      domain: 'text_eq',
      keys: v3WireKeys<TextEqQuery>()('v', 'i', 'hm'),
    },
    {
      column: 'count',
      plaintext: 123456,
      indexType: 'ore',
      domain: 'integer_ord_ore',
      keys: v3WireKeys<IntegerOrdOreQuery>()('v', 'i', 'ob'),
    },
    {
      column: 'rank',
      plaintext: 7,
      indexType: 'ope',
      domain: 'integer_ord_ope',
      keys: v3WireKeys<IntegerOrdOpeQuery>()('v', 'i', 'op'),
    },
  ]

  test.each(scalarQueryCases)(
    'scalar $indexType query on $column returns a term-only eql_v3.query_$domain operand',
    async ({ column, plaintext, indexType, domain, keys }) => {
      const result = await encryptQuery(client, {
        plaintext,
        column,
        table: 'v3users',
        indexType,
      })

      const operand = expectV3QueryOperand(result)
      expect(
        Object.keys(operand).sort(),
        `the operand must target eql_v3.query_${domain}`,
      ).toEqual(keys)
    },
  )

  test('selector query returns the bare selector hash as a string', async () => {
    const selector = await encryptQuery(client, {
      plaintext: '$.role',
      column: 'profile',
      table: 'v3users',
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector',
    })

    expect(selector).toBeTypeOf('string')
    expect((selector as string).length).toBeGreaterThan(0)

    // The selector is the same encoding SteVec entries carry in `s`: an
    // encrypted document containing that path must have a matching entry.
    const doc = (await encrypt(client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
    })) as SteVecDocument
    expect(doc.sv.map((entry) => entry.s)).toContain(selector)
  })

  test('encryptQueryBulk mixes scalar, containment, and selector operands', async () => {
    const results = await encryptQueryBulk(client, {
      queries: [
        {
          plaintext: 'bulk@example.com',
          column: 'email',
          table: 'v3users',
          indexType: 'unique',
        },
        {
          plaintext: { role: 'admin' },
          column: 'profile',
          table: 'v3users',
          indexType: 'ste_vec',
        },
        {
          plaintext: '$.role',
          column: 'profile',
          table: 'v3users',
          indexType: 'ste_vec',
          queryOp: 'ste_vec_selector',
        },
        {
          plaintext: 42,
          column: 'count',
          table: 'v3users',
          indexType: 'ore',
        },
      ],
    })

    expect(results).toHaveLength(4)
    expect(Object.keys(expectV3QueryOperand(results[0])).sort()).toEqual(
      v3WireKeys<TextSearchOreQuery>()('v', 'i', 'hm', 'ob', 'bf'),
    )
    const needle = results[1] as Record<string, unknown>
    expect(needle.v).toBeUndefined()
    expect(Array.isArray(needle.sv)).toBe(true)
    expect(results[2]).toBeTypeOf('string')
    expect(Object.keys(expectV3QueryOperand(results[3])).sort()).toEqual(
      v3WireKeys<IntegerOrdOreQuery>()('v', 'i', 'ob'),
    )
  })
})

describe('isEncrypted', async () => {
  const v2Client = await newClient({ encryptConfig: v3Config })
  const v3Client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('recognises v2 payloads', async () => {
    const ciphertext = await encrypt(v2Client, {
      plaintext: 'v2@example.com',
      column: 'email',
      table: 'v3users',
    })
    expect(isEncrypted(ciphertext)).toBe(true)
  })

  test('recognises v3 payloads', async () => {
    const scalar = await encrypt(v3Client, {
      plaintext: 'v3@example.com',
      column: 'email',
      table: 'v3users',
    })
    const steVec = await encrypt(v3Client, {
      plaintext: { role: 'admin' },
      column: 'profile',
      table: 'v3users',
    })
    expect(isEncrypted(scalar)).toBe(true)
    expect(isEncrypted(steVec)).toBe(true)
  })

  test('rejects plaintext and garbage', () => {
    expect(isEncrypted('some plaintext')).toBe(false)
    expect(isEncrypted(42)).toBe(false)
    expect(isEncrypted(null)).toBe(false)
    expect(isEncrypted({ random: 'data' })).toBe(false)
    expect(isEncrypted({ v: 2, i: { t: 'users', c: 'email' } })).toBe(false)
  })
})

describe('mixed-version decrypt (data migration)', async () => {
  const v2Config: EncryptConfig = {
    v: 1,
    tables: {
      v3users: {
        email: {
          cast_as: 'string',
          indexes: { unique: {} },
        },
      },
    },
  }
  const v2Client = await newClient({ encryptConfig: v2Config, eqlVersion: 2 })
  const v3Client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })

  test('a v3 client decrypts v2 payloads', async () => {
    const ciphertext = await encrypt(v2Client, {
      plaintext: 'migrate-me',
      column: 'email',
      table: 'v3users',
    })
    expect((ciphertext as Record<string, unknown>).k).toBe('ct')

    const decrypted = await decrypt(v3Client, { ciphertext })
    expect(decrypted).toBe('migrate-me')
  })

  test('a v2 client decrypts v3 payloads', async () => {
    const ciphertext = await encrypt(v3Client, {
      plaintext: 'migrate-me-back',
      column: 'email',
      table: 'v3users',
    })
    expect((ciphertext as Record<string, unknown>).v).toBe(3)

    const decrypted = await decrypt(v2Client, { ciphertext })
    expect(decrypted).toBe('migrate-me-back')
  })

  test('a v2 client decrypts v3 SteVec documents', async () => {
    const profile = { migrated: true }
    const ciphertext = await encrypt(v3Client, {
      plaintext: profile,
      column: 'profile',
      table: 'v3users',
    })

    const decrypted = await decrypt(v2Client, { ciphertext })
    expect(decrypted).toEqual(profile)
  })

  test('decryptBulk round-trips a mixed v2 + v3 batch', async () => {
    const v2Ciphertext = await encrypt(v2Client, {
      plaintext: 'still-v2',
      column: 'email',
      table: 'v3users',
    })
    const v3Ciphertext = await encrypt(v3Client, {
      plaintext: 'already-v3',
      column: 'email',
      table: 'v3users',
    })
    expect((v2Ciphertext as Record<string, unknown>).k).toBe('ct')
    expect((v3Ciphertext as Record<string, unknown>).v).toBe(3)

    const decrypted = await decryptBulk(v3Client, {
      ciphertexts: [{ ciphertext: v2Ciphertext }, { ciphertext: v3Ciphertext }],
    })
    expect(decrypted).toEqual(['still-v2', 'already-v3'])
  })

  test('decryptBulkFallible round-trips a mixed v3 + v2 batch', async () => {
    const v3Ciphertext = await encrypt(v3Client, {
      plaintext: 'fallible-v3',
      column: 'email',
      table: 'v3users',
    })
    const v2Ciphertext = await encrypt(v2Client, {
      plaintext: 'fallible-v2',
      column: 'email',
      table: 'v3users',
    })

    const results = await decryptBulkFallible(v2Client, {
      ciphertexts: [{ ciphertext: v3Ciphertext }, { ciphertext: v2Ciphertext }],
    })
    expect(results).toEqual([{ data: 'fallible-v3' }, { data: 'fallible-v2' }])
  })
})

describe('eql v3 configuration errors', () => {
  test('newClient rejects an invalid eqlVersion', async () => {
    const attempt = newClient({
      encryptConfig: v3Config,
      // biome-ignore lint/suspicious/noExplicitAny: deliberately invalid
      eqlVersion: 4 as any,
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'INVALID_EQL_VERSION',
    })
  })

  test('encrypting an indexed boolean under v3 fails with a hint', async () => {
    const config: EncryptConfig = {
      v: 1,
      tables: {
        v3users: {
          flagged: { cast_as: 'boolean', indexes: { unique: {} } },
        },
      },
    }
    const client = await newClient({ encryptConfig: config, eqlVersion: 3 })

    const attempt = encrypt(client, {
      plaintext: true,
      column: 'flagged',
      table: 'v3users',
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_UNSUPPORTED_COLUMN',
    })
    await expect(attempt).rejects.toThrowError(/storage-only/)
  })

  test('encrypting ordered-only text under v3 fails with a hint', async () => {
    const config: EncryptConfig = {
      v: 1,
      tables: {
        v3users: {
          ranked: { cast_as: 'text', indexes: { ore: {} } },
        },
      },
    }
    const client = await newClient({ encryptConfig: config, eqlVersion: 3 })

    const attempt = encrypt(client, {
      plaintext: 'zzz',
      column: 'ranked',
      table: 'v3users',
    })

    await expect(attempt).rejects.toMatchObject({
      code: 'EQL_V3_UNSUPPORTED_COLUMN',
    })
    await expect(attempt).rejects.toThrowError(/unique/)
  })

  // Typed as EncryptedV3 so tsc verifies the exported union is usable.
  test('the EncryptedV3 union types v3 payloads', async () => {
    const client = await newClient({ encryptConfig: v3Config, eqlVersion: 3 })
    const ciphertext = (await encrypt(client, {
      plaintext: 'typed',
      column: 'name',
      table: 'v3users',
    })) as EncryptedV3

    expect(ciphertext.v).toBe(3)
  })
})
