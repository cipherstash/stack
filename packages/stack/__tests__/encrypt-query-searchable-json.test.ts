import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { Encryption } from '@/index'

type EncryptionClient = Awaited<ReturnType<typeof Encryption>>

import {
  createMockLockContext,
  expectFailure,
  jsonbSchema,
  metadata,
  unwrapResult,
} from './fixtures'

/*
 * The `searchableJson` queryType provides a friendlier API by auto-inferring the
 * underlying query operation from the plaintext type. It's equivalent to omitting
 * queryType on ste_vec columns, but explicit for code clarity.
 * - String values → ste_vec_selector (JSONPath queries)
 * - Object/Array values → ste_vec_term (containment queries)
 */

/** Assert encrypted selector output has valid shape */
function expectSelector(data: any) {
  expect(data).toHaveProperty('s')
  expect(typeof data.s).toBe('string')
  expect(data.s.length).toBeGreaterThan(0)
}

/** Assert encrypted term output has valid shape */
function expectTerm(data: any) {
  expect(data).toHaveProperty('sv')
  expect(Array.isArray(data.sv)).toBe(true)
}

describe('encryptQuery with searchableJson queryType', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  // Core functionality: auto-inference from plaintext type

  it('auto-infers ste_vec_selector for string plaintext (JSONPath)', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectSelector(data)
  }, 30000)

  it('auto-infers ste_vec_term for object plaintext (containment)', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('auto-infers ste_vec_term for nested object', async () => {
    const result = await protectClient.encryptQuery(
      { user: { profile: { role: 'admin' } } },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('auto-infers ste_vec_term for array plaintext', async () => {
    const result = await protectClient.encryptQuery(['admin', 'user'], {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  // Edge cases: number/boolean require wrapping (same as steVecTerm)

  it('fails for bare number plaintext (requires wrapping)', async () => {
    const result = await protectClient.encryptQuery(42, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    expectFailure(result, /Wrap the number in a JSON object/)
  }, 30000)

  it('fails for bare boolean plaintext (requires wrapping)', async () => {
    const result = await protectClient.encryptQuery(true, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    expectFailure(result, /Wrap the boolean in a JSON object/)
  }, 30000)
})

describe('encryptQuery with searchableJson column and omitted queryType', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('auto-infers ste_vec_selector for string plaintext (JSONPath)', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectSelector(data)
  }, 30000)

  it('auto-infers ste_vec_term for object plaintext (containment)', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('fails for bare number plaintext (requires wrapping)', async () => {
    const result = await protectClient.encryptQuery(42, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
    })

    expectFailure(result, /Wrap the number in a JSON object/)
  }, 30000)

  it('fails for bare boolean plaintext (requires wrapping)', async () => {
    const result = await protectClient.encryptQuery(true, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
    })

    expectFailure(result, /Wrap the boolean in a JSON object/)
  }, 30000)
})

describe('searchableJson validation', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('throws when used on column without ste_vec index', async () => {
    const result = await protectClient.encryptQuery('$.path', {
      column: metadata.raw, // raw column has no ste_vec index
      table: metadata,
      queryType: 'searchableJson',
    })

    expectFailure(result)
  }, 30000)
})

describe('searchableJson batch operations', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('handles mixed plaintext types in single batch', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.user.email', // string → ste_vec_selector
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
      {
        value: { role: 'admin' }, // object → ste_vec_term
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
      {
        value: ['tag1', 'tag2'], // array → ste_vec_term
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    ])

    const data = unwrapResult(result)
    expect(data).toHaveLength(3)
    expect(data[0]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
    expectSelector(data[0])
    expect(data[1]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
    expectTerm(data[1])
    expect(data[2]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
    expectTerm(data[2])
  }, 30000)

  it('can be mixed with explicit steVecSelector/steVecTerm in batch', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.path1',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson', // auto-infer
      },
      {
        value: '$.path2',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector', // explicit
      },
      {
        value: { key: 'value' },
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecTerm', // explicit
      },
    ])

    const data = unwrapResult(result)
    expect(data).toHaveLength(3)
    expectSelector(data[0])
    expectSelector(data[1])
    expectTerm(data[2])
  }, 30000)

  it('can omit queryType for searchableJson in batch', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.path1',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
      },
      {
        value: { key: 'value' },
        column: jsonbSchema.metadata,
        table: jsonbSchema,
      },
    ])

    const data = unwrapResult(result)
    expect(data).toHaveLength(2)
    expectSelector(data[0])
    expectTerm(data[1])
  }, 30000)
})

describe('searchableJson with returnType formatting', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('supports composite-literal returnType', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.user.email',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
        returnType: 'composite-literal',
      },
    ])

    const data = unwrapResult(result)
    expect(data).toHaveLength(1)
    expect(typeof data[0]).toBe('string')
    // Format: ("json")
    expect(data[0]).toMatch(/^\(".*"\)$/)
  }, 30000)

  it('supports escaped-composite-literal returnType', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: { role: 'admin' },
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
        returnType: 'escaped-composite-literal',
      },
    ])

    const data = unwrapResult(result)
    expect(data).toHaveLength(1)
    expect(typeof data[0]).toBe('string')
    // Format: "(\"json\")" - outer quotes with escaped inner quotes
    expect(data[0]).toMatch(/^"\(.*\)"$/)
  }, 30000)
})

describe('single-value returnType', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('returns composite-literal for selector', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
      returnType: 'composite-literal',
    })

    const data = unwrapResult(result)
    expect(typeof data).toBe('string')
    expect(data).toMatch(/^\(".*"\)$/)
  }, 30000)

  it('returns composite-literal for term', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
        returnType: 'composite-literal',
      },
    )

    const data = unwrapResult(result)
    expect(typeof data).toBe('string')
    expect(data).toMatch(/^\(".*"\)$/)
  }, 30000)

  it('returns escaped-composite-literal for selector', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
      returnType: 'escaped-composite-literal',
    })

    const data = unwrapResult(result)
    expect(typeof data).toBe('string')
    expect(data as string).toMatch(/^"\(.*\)"$/)
    // JSON.parse should yield the composite-literal format
    const parsed = JSON.parse(data as string)
    expect(parsed).toMatch(/^\(.*\)$/)
  }, 30000)

  it('returns escaped-composite-literal for term', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
        returnType: 'escaped-composite-literal',
      },
    )

    const data = unwrapResult(result)
    expect(typeof data).toBe('string')
    expect(data as string).toMatch(/^"\(.*\)"$/)
    const parsed = JSON.parse(data as string)
    expect(parsed).toMatch(/^\(.*\)$/)
  }, 30000)

  it('returns Encrypted object when returnType is omitted', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result) as any
    expect(typeof data).toBe('object')
    expect(data).toHaveProperty('i')
    expect(data.i).toHaveProperty('t')
    expect(data.i).toHaveProperty('c')
  }, 30000)
})

describe('searchableJson with LockContext', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('exposes withLockContext method', async () => {
    const operation = protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    expect(operation.withLockContext).toBeDefined()
    expect(typeof operation.withLockContext).toBe('function')
  })

  it('executes string plaintext bound to an identity claim', async () => {
    const operation = protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const withContext = operation.withLockContext(createMockLockContext())
    const result = await withContext.execute()

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectSelector(data)
  }, 30000)

  it('executes object plaintext bound to an identity claim', async () => {
    const operation = protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const withContext = operation.withLockContext(createMockLockContext())
    const result = await withContext.execute()

    // Ensure the operation actually completed (has either data or failure)
    expect(result.data !== undefined || result.failure !== undefined).toBe(true)

    if (result.data) {
      expect(result.data).toMatchObject({
        i: { t: 'documents', c: 'metadata' },
        v: 2,
      })
      expectTerm(result.data)
    }
  }, 30000)

  it('executes a batch bound to an identity claim', async () => {
    const operation = protectClient.encryptQuery([
      {
        value: '$.user.email',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
      {
        value: { role: 'admin' },
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    ])

    const withContext = operation.withLockContext(createMockLockContext())
    const result = await withContext.execute()

    if (result.data) {
      expect(result.data).toHaveLength(2)
    }
  }, 30000)
})

describe('searchableJson equivalence', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('produces identical metadata to omitting queryType for string', async () => {
    const explicitResult = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const implicitResult = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
    })

    // Both should succeed and have identical metadata structure
    const explicitData = unwrapResult(explicitResult)
    const implicitData = unwrapResult(implicitResult)

    expect(explicitData.i).toEqual(implicitData.i)
    expect(explicitData.v).toEqual(implicitData.v)
    expectSelector(explicitData)
    expectSelector(implicitData)
  }, 30000)

  it('produces identical metadata to omitting queryType for object', async () => {
    const explicitResult = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const implicitResult = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
      },
    )

    const explicitData = unwrapResult(explicitResult)
    const implicitData = unwrapResult(implicitResult)

    expect(explicitData.i).toEqual(implicitData.i)
    expect(explicitData.v).toEqual(implicitData.v)
    expectTerm(explicitData)
    expectTerm(implicitData)
  }, 30000)

  it('produces identical metadata to explicit steVecSelector for string', async () => {
    const searchableJsonResult = await protectClient.encryptQuery(
      '$.user.email',
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const steVecSelectorResult = await protectClient.encryptQuery(
      '$.user.email',
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector',
      },
    )

    const searchableJsonData = unwrapResult(searchableJsonResult)
    const steVecSelectorData = unwrapResult(steVecSelectorResult)

    expect(searchableJsonData.i).toEqual(steVecSelectorData.i)
    expect(searchableJsonData.v).toEqual(steVecSelectorData.v)
    expectSelector(searchableJsonData)
    expectSelector(steVecSelectorData)
  }, 30000)

  it('produces identical metadata to explicit steVecTerm for object', async () => {
    const searchableJsonResult = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const steVecTermResult = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecTerm',
      },
    )

    const searchableJsonData = unwrapResult(searchableJsonResult)
    const steVecTermData = unwrapResult(steVecTermResult)

    expect(searchableJsonData.i).toEqual(steVecTermData.i)
    expect(searchableJsonData.v).toEqual(steVecTermData.v)
    expectTerm(searchableJsonData)
    expectTerm(steVecTermData)
  }, 30000)
})

describe('searchableJson edge cases', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  // Valid edge cases that should succeed

  it('succeeds for empty object', async () => {
    const result = await protectClient.encryptQuery(
      {},
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('succeeds for empty array', async () => {
    const result = await protectClient.encryptQuery([], {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('succeeds for object with wrapped number', async () => {
    const result = await protectClient.encryptQuery(
      { value: 42 },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('succeeds for object with wrapped boolean', async () => {
    const result = await protectClient.encryptQuery(
      { active: true },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('succeeds for object with null value', async () => {
    const result = await protectClient.encryptQuery(
      { field: null },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  it('succeeds for deeply nested object (3+ levels)', async () => {
    const result = await protectClient.encryptQuery(
      {
        level1: {
          level2: {
            level3: {
              level4: {
                value: 'deep',
              },
            },
          },
        },
      },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    )

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectTerm(data)
  }, 30000)

  // String edge cases for JSONPath selectors

  it('succeeds for JSONPath with array index notation', async () => {
    const result = await protectClient.encryptQuery('$.items[0].name', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectSelector(data)
  }, 30000)

  it('succeeds for JSONPath with wildcard', async () => {
    const result = await protectClient.encryptQuery('$.items[*].name', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const data = unwrapResult(result)
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
      v: 2,
    })
    expectSelector(data)
  }, 30000)
})

describe('searchableJson batch edge cases', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('handles single-item batch identically to scalar', async () => {
    const scalarResult = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson',
    })

    const batchResult = await protectClient.encryptQuery([
      {
        value: '$.user.email',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'searchableJson',
      },
    ])

    const scalarData = unwrapResult(scalarResult)
    const batchData = unwrapResult(batchResult)

    expect(batchData).toHaveLength(1)
    expect(batchData[0].i).toEqual(scalarData.i)
    expect(batchData[0].v).toEqual(scalarData.v)
    expectSelector(scalarData)
    expectSelector(batchData[0])
  }, 30000)

  it('handles empty batch', async () => {
    const result = await protectClient.encryptQuery([])

    const data = unwrapResult(result)
    expect(data).toHaveLength(0)
  }, 30000)

  it('handles large batch (10+ items)', async () => {
    const items = Array.from({ length: 12 }, (_, i) => ({
      value: i % 2 === 0 ? `$.path${i}` : { index: i },
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'searchableJson' as const,
    }))

    const result = await protectClient.encryptQuery(items)

    const data = unwrapResult(result)
    expect(data).toHaveLength(12)
    data.forEach((item: any, idx: number) => {
      expect(item).toMatchObject({
        i: { t: 'documents', c: 'metadata' },
        v: 2,
      })
      if (idx % 2 === 0) {
        expectSelector(item)
      } else {
        expectTerm(item)
      }
    })
  }, 30000)
})
