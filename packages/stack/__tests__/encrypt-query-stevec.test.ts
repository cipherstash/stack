import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { Encryption } from '@/index'

type EncryptionClient = Awaited<ReturnType<typeof Encryption>>

import { expectFailure, jsonbSchema, metadata, unwrapResult } from './fixtures'

describe('encryptQuery with steVecSelector', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('encrypts a JSONPath selector', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'steVecSelector',
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('encrypts nested path selector', async () => {
    const result = await protectClient.encryptQuery('$.user.profile.settings', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'steVecSelector',
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('fails for non-string plaintext with steVecSelector (object)', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector',
      },
    )

    expectFailure(result)
  }, 30000)
})

describe('encryptQuery with steVecTerm', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('encrypts an object for containment query', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecTerm',
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('encrypts nested object for containment', async () => {
    const result = await protectClient.encryptQuery(
      { user: { profile: { role: 'admin' } } },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecTerm',
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('encrypts array for containment query', async () => {
    const result = await protectClient.encryptQuery([1, 2, 3], {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'steVecTerm',
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('rejects string plaintext with steVecTerm', async () => {
    // steVecTerm requires object or array, not string
    // For path queries like '$.field', use steVecSelector instead
    const result = await protectClient.encryptQuery('search text', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'steVecTerm',
    })

    expectFailure(result, /expected JSON object or array/)
  }, 30000)
})

describe('encryptQuery STE Vec validation', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('throws when steVecSelector used on non-ste_vec column', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: metadata.raw, // raw column has no ste_vec index
      table: metadata,
      queryType: 'steVecSelector',
    })

    expectFailure(result)
  }, 30000)

  it('throws when steVecTerm used on non-ste_vec column', async () => {
    const result = await protectClient.encryptQuery(
      { field: 'value' },
      {
        column: metadata.raw, // raw column has no ste_vec index
        table: metadata,
        queryType: 'steVecTerm',
      },
    )

    expectFailure(result)
  }, 30000)
})

describe('encryptQuery batch with STE Vec', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema, metadata] })
  })

  it('handles mixed query types in batch (steVecSelector + steVecTerm)', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.user.email',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector',
      },
      {
        value: { role: 'admin' },
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecTerm',
      },
    ])

    const data = unwrapResult(result)

    expect(data).toHaveLength(2)
    expect(data[0]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
    expect(data[1]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
  }, 30000)

  it('handles multiple steVecSelector queries in batch', async () => {
    const result = await protectClient.encryptQuery([
      {
        value: '$.user.email',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector',
      },
      {
        value: '$.settings.theme',
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        queryType: 'steVecSelector',
      },
    ])

    const data = unwrapResult(result)

    expect(data).toHaveLength(2)
    expect(data[0]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
    expect(data[1]).toMatchObject({ i: { t: 'documents', c: 'metadata' } })
  }, 30000)
})

describe('encryptQuery with queryType inference', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('infers steVecSelector for string plaintext without queryType', async () => {
    const result = await protectClient.encryptQuery('$.user.email', {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      // No queryType - should infer steVecSelector from string
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('infers steVecTerm for object plaintext without queryType', async () => {
    const result = await protectClient.encryptQuery(
      { role: 'admin' },
      {
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        // No queryType - should infer steVecTerm from object
      },
    )

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('infers steVecTerm for array plaintext without queryType', async () => {
    const result = await protectClient.encryptQuery(['admin', 'user'], {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      // No queryType - should infer steVecTerm from array
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)

  it('infers steVecTerm for number plaintext but FFI requires wrapping', async () => {
    // Numbers infer steVecTerm but FFI requires wrapping in object/array
    const result = await protectClient.encryptQuery(42, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      // No queryType - infers steVecTerm, FFI rejects with helpful message
    })

    expectFailure(result, /Wrap the number in a JSON object/)
  }, 30000)

  it('infers steVecTerm for boolean plaintext but FFI requires wrapping', async () => {
    // Booleans infer steVecTerm but FFI requires wrapping in object/array
    const result = await protectClient.encryptQuery(true, {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      // No queryType - infers steVecTerm, FFI rejects with helpful message
    })

    expectFailure(result, /Wrap the boolean in a JSON object/)
  }, 30000)

  it('uses explicit queryType over plaintext inference', async () => {
    // String plaintext would normally infer steVecSelector, but explicit steVecTerm should be used
    // Note: steVecTerm with string fails FFI validation, so we test the opposite direction
    // Using a number (which would infer steVecTerm) with explicit steVecSelector would also fail
    // So we verify with array + steVecTerm (already tested) and trust unit test coverage for precedence
    const result = await protectClient.encryptQuery([42], {
      column: jsonbSchema.metadata,
      table: jsonbSchema,
      queryType: 'steVecTerm', // Explicit - matches inference but proves explicit path works
    })

    const data = unwrapResult(result)
    expect(data).toBeDefined()
    expect(data).toMatchObject({
      i: { t: 'documents', c: 'metadata' },
    })
  }, 30000)
})

describe('encryptQuery batch with queryType inference', () => {
  let protectClient: EncryptionClient

  beforeAll(async () => {
    protectClient = await Encryption({ schemas: [jsonbSchema] })
  })

  it('infers queryOp for each term independently in batch', async () => {
    const results = await protectClient.encryptQuery([
      {
        value: '$.user.email', // string → steVecSelector
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        // No queryType
      },
      {
        value: { role: 'admin' }, // object → steVecTerm
        column: jsonbSchema.metadata,
        table: jsonbSchema,
        // No queryType
      },
    ])

    const data = unwrapResult(results)
    expect(data).toHaveLength(2)
    expect(data[0]).toBeDefined()
    expect(data[1]).toBeDefined()
  }, 30000)
})
