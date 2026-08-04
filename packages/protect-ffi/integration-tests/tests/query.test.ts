import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type EncryptConfig,
  type Identifier,
  type QueryPayload,
  encryptQuery,
  encryptQueryBulk,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared encryptConfig from common.js
import { encryptConfig } from './common.js'

type V3ScalarQuery = {
  v: number
  i: { t: string; c: string }
  c?: never
  k?: never
  hm?: string
  bf?: number[]
  ob?: string[]
  op?: string
}

function assertScalar(payload: unknown): asserts payload is V3ScalarQuery {
  if (typeof payload !== 'object' || payload === null || !('i' in payload)) {
    throw new Error('expected an EQL v3 scalar query operand')
  }
  expect(payload).not.toHaveProperty('c')
  expect(payload).not.toHaveProperty('k')
}

type UserColumn = Identifier<typeof encryptConfig>

const emailColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

const scoreColumn: UserColumn = {
  table: 'users',
  column: 'score',
}

const profileColumn: UserColumn = {
  table: 'users',
  column: 'profile',
}

describe('encryptQuery for ste_vec indexes', () => {
  test('should encrypt JSON path selector for ste_vec columns with SEM only payloads', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: '$.name',
      ...profileColumn,
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector',
    })

    expect(result).toBeTypeOf('string')
  })

  test('should handle different JSON path selectors for ste_vec', async () => {
    const client = await newClient({ encryptConfig })

    const selectors = ['$.name', '$.email', '$.profile.address']

    for (const selector of selectors) {
      const result = await encryptQuery(client, {
        plaintext: selector,
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_selector',
      })

      expect(result).toBeTypeOf('string')
    }
  })

  test('should encrypt with default operation for ste_vec without explicit queryOp', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: { tag: 'important' },
      ...profileColumn,
      indexType: 'ste_vec',
    })

    console.log('OBJECT + DEFAULT queryOp output:')
    console.log(JSON.stringify(result, null, 2))

    // A v3 containment needle has no storage envelope.
    expect(result).toHaveProperty('sv') // Flattened entries for containment matching
    expect(Array.isArray((result as { sv: unknown }).sv)).toBe(true)
    expect(result).not.toHaveProperty('c')
    expect(result).not.toHaveProperty('i')
    expect(result).not.toHaveProperty('v')
  })

  test('should encrypt string path with explicit ste_vec_selector', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: '$.tag',
      ...profileColumn,
      indexType: 'ste_vec',
      queryOp: 'ste_vec_selector', // Must be explicit!
    })

    console.log('STRING + STE_VEC_SELECTOR output:')
    console.log(JSON.stringify(result, null, 2))

    expect(result).toBeTypeOf('string')
  })
})

describe('encryptQuery for string indexes', () => {
  test('should encrypt for ORE index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test@example.com',
      ...emailColumn,
      indexType: 'ore',
    })

    // ORE queries should have SEM fields
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('ob') // ORE blocks for range queries
    assertScalar(result)
    expect(Array.isArray(result.ob)).toBe(true)
  })

  test('should encrypt for match index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test',
      ...emailColumn,
      indexType: 'match',
    })

    // Match index should include bloom filter
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('bf') // bloom filter for fuzzy/substring match
    assertScalar(result)
    expect(Array.isArray(result.bf)).toBe(true)
  })

  test('should encrypt for unique index on string column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 'test@example.com',
      ...emailColumn,
      indexType: 'unique',
    })

    // Unique index should have HMAC
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('hm') // HMAC for exact match queries
    assertScalar(result)
    expect(typeof result.hm).toBe('string')
  })
})

describe('encryptQuery for numeric indexes', () => {
  test('should encrypt for ORE index on integer column', async () => {
    const client = await newClient({ encryptConfig })

    const result = await encryptQuery(client, {
      plaintext: 100,
      ...scoreColumn,
      indexType: 'ore',
    })

    // ORE queries should have SEM fields
    expect(result).toHaveProperty('i')
    expect(result).toHaveProperty('v')
    expect(result).toHaveProperty('ob') // ORE blocks for range queries
    assertScalar(result)
    expect(Array.isArray(result.ob)).toBe(true)
  })

  test('should encrypt for ORE index with a bigint query term', async () => {
    const client = await newClient({ encryptConfig })

    // Query terms are generated from the same Plaintext as storage terms,
    // so a bigint beyond Number.MAX_SAFE_INTEGER stays exact here too.
    const result = await encryptQuery(client, {
      plaintext: 2n ** 60n,
      ...scoreColumn,
      indexType: 'ore',
    })

    assertScalar(result)
    expect(result).toHaveProperty('ob')
    expect(Array.isArray(result.ob)).toBe(true)
  })

  test('should reject a bigint query term outside the i64 range', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 2n ** 63n,
        ...scoreColumn,
        indexType: 'ore',
      }),
    ).rejects.toThrowError(/above the maximum.*signed 64-bit integer/)
  })
})

describe('encryptQueryBulk for query ordering and grouping', () => {
  test('should encrypt multiple queries in order', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: 'test1@example.com',
        ...emailColumn,
        indexType: 'ore',
      },
      {
        plaintext: 'test2@example.com',
        ...emailColumn,
        indexType: 'match',
      },
      {
        plaintext: 'test3@example.com',
        ...emailColumn,
        indexType: 'unique',
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(Array.isArray(results)).toBe(true)
    expect(results).toHaveLength(3)

    // First should be ORE
    expect(results[0]).toHaveProperty('ob')

    // Second should be match
    expect(results[1]).toHaveProperty('bf')

    // Third should be unique
    expect(results[2]).toHaveProperty('hm')
  })

  test('should handle mixed index types across columns in bulk', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: '$.status',
        ...profileColumn,
        indexType: 'ste_vec',
        queryOp: 'ste_vec_selector',
      },
      {
        plaintext: 'john@example.com',
        ...emailColumn,
        indexType: 'match',
      },
      {
        plaintext: 150,
        ...scoreColumn,
        indexType: 'ore',
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(3)

    // First should be ste_vec (no 'c' field)
    expect(results[0]).not.toHaveProperty('c')

    // Second should have match bloom filter
    expect(results[1]).toHaveProperty('bf')

    // Third should have ORE fields
    expect(results[2]).toHaveProperty('ob')
  })

  test('should forward lockContext for bulk queries', async () => {
    const client = await newClient({ encryptConfig })
    const lockContext = {
      identityClaim: ['user123'],
    }

    const queries: QueryPayload[] = [
      {
        plaintext: 'email1@example.com',
        ...emailColumn,
        indexType: 'ore',
        lockContext,
      },
      {
        plaintext: 'email2@example.com',
        ...emailColumn,
        indexType: 'match',
        lockContext,
      },
    ]

    // The integration-test client is not a service token. ZeroKMS rejecting
    // the identity claim proves the bulk path forwarded the lock context;
    // silently dropping it would make this request succeed.
    await expect(encryptQueryBulk(client, { queries })).rejects.toThrowError(
      /Request forbidden/,
    )
  }, 10000)

  test('should preserve order with identical index types and different plaintexts', async () => {
    const client = await newClient({ encryptConfig })

    const plaintexts = [
      'alice@example.com',
      'bob@example.com',
      'charlie@example.com',
    ]
    const queries: QueryPayload[] = plaintexts.map((plaintext) => ({
      plaintext,
      ...emailColumn,
      indexType: 'unique',
    }))

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(3)
    // All should have HMAC (unique index)
    expect(results[0]).toHaveProperty('hm')
    expect(results[1]).toHaveProperty('hm')
    expect(results[2]).toHaveProperty('hm')
    assertScalar(results[0])
    assertScalar(results[1])
    assertScalar(results[2])
    // Results should be different (different plaintexts)
    expect(results[0].hm).not.toEqual(results[1].hm)
    expect(results[1].hm).not.toEqual(results[2].hm)
  })

  test('should encrypt a bigint query term in bulk (mixed with strings)', async () => {
    const client = await newClient({ encryptConfig })

    // A bigint element exercises the clone branch of
    // `withEncodedPlaintexts(opts.queries)` in `encryptQueryBulk` — the
    // single-query test above covers `withEncodedPlaintext`, but the bulk
    // wrapper's array rewrite is a separate path (mirrors what
    // scalar-bulk.test.ts does for encryptBulk).
    const queries: QueryPayload[] = [
      {
        plaintext: 'test1@example.com',
        ...emailColumn,
        indexType: 'unique',
      },
      {
        plaintext: 2n ** 60n,
        ...scoreColumn,
        indexType: 'ore',
      },
    ]

    const results = await encryptQueryBulk(client, { queries })

    expect(results).toHaveLength(2)
    expect(results[0]).toHaveProperty('hm')
    expect(results[1]).toHaveProperty('ob')
    assertScalar(results[1])
  })

  test('should reject an out-of-range bigint query term in bulk with a RangeError', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQueryBulk(client, {
        queries: [
          {
            plaintext: 2n ** 63n,
            ...scoreColumn,
            indexType: 'ore',
          },
        ],
      }),
    ).rejects.toThrowError(/above the maximum.*signed 64-bit integer/)
  })
})

describe('encryptQuery error handling', () => {
  test('should error for missing column', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        table: 'users',
        column: 'nonexistent',
        indexType: 'ore',
      }),
    ).rejects.toThrowError()
  })

  test('should include error code for missing column', async () => {
    const client = await newClient({ encryptConfig })

    try {
      await encryptQuery(client, {
        plaintext: 'test',
        table: 'users',
        column: 'nonexistent',
        indexType: 'ore',
      })
      throw new Error('expected encryptQuery to throw')
    } catch (err) {
      expect(err).toBeInstanceOf(Error)
      expect((err as { code?: unknown }).code).toBe('UNKNOWN_COLUMN')
    }
  })

  test('should error for missing index type', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        ...emailColumn,
        // biome-ignore lint/suspicious/noExplicitAny: testing invalid input
        indexType: 'nonexistent' as any,
      }),
    ).rejects.toThrowError()
  })

  test('should preserve the error code for an unknown queryOp', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQuery(client, {
        plaintext: 'test',
        ...profileColumn,
        indexType: 'ste_vec',
        // biome-ignore lint/suspicious/noExplicitAny: testing invalid input
        queryOp: 'invalid_op' as any,
      }),
    ).rejects.toMatchObject({
      code: 'UNKNOWN_QUERY_OP',
      message: expect.stringContaining("Unknown query operation: 'invalid_op'"),
    })
  })
})

describe('encryptQueryBulk error handling', () => {
  test('should handle partial errors in bulk operations', async () => {
    const client = await newClient({ encryptConfig })

    const queries: QueryPayload[] = [
      {
        plaintext: 'test@example.com',
        ...emailColumn,
        indexType: 'ore',
      },
      {
        plaintext: 'test',
        table: 'users',
        column: 'nonexistent',
        indexType: 'ore',
      },
    ]

    // Bulk operations should fail if any query is invalid
    await expect(encryptQueryBulk(client, { queries })).rejects.toThrowError()
  })

  test('should preserve the error code for an unknown queryOp', async () => {
    const client = await newClient({ encryptConfig })

    await expect(
      encryptQueryBulk(client, {
        queries: [
          {
            plaintext: 'test',
            ...profileColumn,
            indexType: 'ste_vec',
            // biome-ignore lint/suspicious/noExplicitAny: testing invalid input
            queryOp: 'invalid_op' as any,
          },
        ],
      }),
    ).rejects.toMatchObject({
      code: 'UNKNOWN_QUERY_OP',
      message: expect.stringContaining("Unknown query operation: 'invalid_op'"),
    })
  })
})

describe('match include_original is storage-only', () => {
  const configWithIncludeOriginal = (
    include_original: boolean,
  ): EncryptConfig => ({
    v: 1,
    tables: {
      users: {
        email: {
          cast_as: 'string',
          indexes: {
            ore: {},
            unique: {},
            match: {
              tokenizer: { kind: 'ngram', token_length: 3 },
              token_filters: [{ kind: 'downcase' }],
              k: 6,
              m: 2048,
              include_original,
            },
          },
        },
      },
    },
  })

  // Bloom bit ORDER is nondeterministic; sort before comparing bit SETS.
  const bloomBits = (payload: unknown): number[] => {
    const bf =
      typeof payload === 'object' && payload !== null && 'bf' in payload
        ? payload.bf
        : undefined
    if (!Array.isArray(bf)) {
      throw new Error('expected a bloom filter on the query payload')
    }
    return [...bf].sort((a, b) => a - b)
  }

  for (const eqlVersion of [2, 3] as const) {
    test(`eqlVersion ${eqlVersion}: query blooms are token-only regardless of the flag`, async () => {
      const flagged = await newClient({
        encryptConfig: configWithIncludeOriginal(true),
        eqlVersion,
      })
      const plain = await newClient({
        encryptConfig: configWithIncludeOriginal(false),
        eqlVersion,
      })

      const query = {
        plaintext: 'ada@example.com',
        ...emailColumn,
        indexType: 'match',
      } as const

      const withFlag = await encryptQuery(flagged, query)
      const withoutFlag = await encryptQuery(plain, query)

      // include_original may add a whole-value term to STORED blooms, but the
      // query bloom must never carry one: EQL matches by bit-subset, so a
      // whole-needle term would make substring queries match nothing (#134).
      // Identical bit sets across the two configs prove the flag is stripped
      // from query generation.
      expect(bloomBits(withFlag)).toEqual(bloomBits(withoutFlag))
    })
  }
})
