import 'dotenv/config'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedField, encryptedTable } from '@/schema'
import { beforeAll, describe, expect, it, test } from 'vitest'

const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
  age: encryptedColumn('age').dataType('number').equality().orderAndRange(),
  score: encryptedColumn('score').dataType('number').equality().orderAndRange(),
  metadata: {
    count: encryptedField('metadata.count').dataType('number'),
    level: encryptedField('metadata.level').dataType('number'),
  },
})

type User = {
  id: string
  email?: string
  createdAt?: Date
  updatedAt?: Date
  address?: string
  age?: number
  score?: number
  metadata?: {
    count?: number
    level?: number
  }
}

let protectClient: Awaited<ReturnType<typeof Encryption>>

beforeAll(async () => {
  protectClient = await Encryption({
    schemas: [users],
  })
})

const cases = [
  25,
  0,
  -42,
  2147483647,
  77.9,
  0.0,
  -117.123456,
  1e15,
  -1e15, // Very large floats
  9007199254740991, // Max safe integer in JavaScript
]

describe('Number encryption and decryption', () => {
  test.each(cases)(
    'should encrypt and decrypt a number: %d',
    async (age) => {
      const ciphertext = await protectClient.encrypt(age, {
        column: users.age,
        table: users,
      })

      if (ciphertext.failure) {
        throw new Error(`[protect]: ${ciphertext.failure.message}`)
      }

      // Verify encrypted field
      expect(ciphertext.data).toHaveProperty('c')

      const plaintext = await protectClient.decrypt(ciphertext.data)

      expect(plaintext).toEqual({
        data: age,
      })
    },
    30000,
  )

  // Special case
  it('should treat a negative zero valued float as 0.0', async () => {
    const score = -0.0

    const ciphertext = await protectClient.encrypt(score, {
      column: users.score,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('c')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: 0.0,
    })
  }, 30000)

  // Special case
  it('should error for a NaN float', async () => {
    const score = Number.NaN

    const result = await protectClient.encrypt(score, {
      column: users.score,
      table: users,
    })

    expect(result.failure).toBeDefined()
    expect(result.failure?.message).toContain('Cannot encrypt NaN value')
  }, 30000)

  // Special case
  it('should error for Infinity', async () => {
    const score = Number.POSITIVE_INFINITY

    const result = await protectClient.encrypt(score, {
      column: users.score,
      table: users,
    })

    expect(result.failure).toBeDefined()
    expect(result.failure?.message).toContain('Cannot encrypt Infinity value')
  }, 30000)

  // Special case
  it('should error for -Infinity', async () => {
    const score = Number.NEGATIVE_INFINITY

    const result = await protectClient.encrypt(score, {
      column: users.score,
      table: users,
    })

    expect(result.failure).toBeDefined()
    expect(result.failure?.message).toContain('Cannot encrypt Infinity value')
  }, 30000)
})

describe('Model encryption and decryption', () => {
  it('should encrypt and decrypt a model with number fields', async () => {
    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      age: 30,
      score: 95,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.age).toHaveProperty('c')
    expect(encryptedModel.data.score).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle null numbers in model', async () => {
    const decryptedModel: User = {
      id: '2',
      email: 'test2@example.com',
      address: '456 Oak St',
      age: undefined,
      score: undefined,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.age).toBeUndefined()
    expect(encryptedModel.data.score).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle undefined numbers in model', async () => {
    const decryptedModel = {
      id: '3',
      email: 'test3@example.com',
      address: '789 Pine St',
      age: undefined,
      score: undefined,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.age).toBeUndefined()
    expect(encryptedModel.data.score).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)
})

describe('Bulk encryption and decryption', () => {
  it('should bulk encrypt and decrypt number payloads', async () => {
    const intPayloads = [
      { id: 'user1', plaintext: 25 },
      { id: 'user2', plaintext: 30.7 },
      { id: 'user3', plaintext: -35.123 },
    ]

    const encryptedData = await protectClient.bulkEncrypt(intPayloads, {
      column: users.age,
      table: users,
    })

    if (encryptedData.failure) {
      throw new Error(`[protect]: ${encryptedData.failure.message}`)
    }

    // Verify structure
    expect(encryptedData.data).toHaveLength(3)
    expect(encryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(encryptedData.data[0]).toHaveProperty('data')
    expect(encryptedData.data[0].data).toHaveProperty('c')
    expect(encryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(encryptedData.data[1]).toHaveProperty('data')
    expect(encryptedData.data[1].data).toHaveProperty('c')
    expect(encryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(encryptedData.data[2]).toHaveProperty('data')
    expect(encryptedData.data[2].data).toHaveProperty('c')

    // EQL v2.3: scalar encryptions carry the `k: 'ct'` discriminator
    expect(encryptedData.data[0].data).toHaveProperty('k', 'ct')
    expect(encryptedData.data[1].data).toHaveProperty('k', 'ct')
    expect(encryptedData.data[2].data).toHaveProperty('k', 'ct')

    // Verify all encrypted values are different
    const getCiphertext = (data: { c?: unknown } | null | undefined) => data?.c

    expect(getCiphertext(encryptedData.data[0].data)).not.toBe(
      getCiphertext(encryptedData.data[1].data),
    )
    expect(getCiphertext(encryptedData.data[1].data)).not.toBe(
      getCiphertext(encryptedData.data[2].data),
    )
    expect(getCiphertext(encryptedData.data[0].data)).not.toBe(
      getCiphertext(encryptedData.data[2].data),
    )

    // Now decrypt the data
    const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

    if (decryptedData.failure) {
      throw new Error(`[protect]: ${decryptedData.failure.message}`)
    }

    // Verify decrypted data
    expect(decryptedData.data).toHaveLength(3)
    expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(decryptedData.data[0]).toHaveProperty('data', 25)
    expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(decryptedData.data[1]).toHaveProperty('data', 30.7)
    expect(decryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(decryptedData.data[2]).toHaveProperty('data', -35.123)
  }, 30000)

  it('should bulk encrypt and decrypt models with number fields', async () => {
    const decryptedModels = [
      {
        id: '1',
        email: 'test1@example.com',
        address: '123 Main St',
        age: 25,
        score: 85,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
      },
      {
        id: '2',
        email: 'test2@example.com',
        address: '456 Oak St',
        age: 30,
        score: 90,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
      },
    ]

    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      decryptedModels,
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toHaveProperty('c')
    expect(encryptedModels.data[0].address).toHaveProperty('c')
    expect(encryptedModels.data[0].age).toHaveProperty('c')
    expect(encryptedModels.data[0].score).toHaveProperty('c')
    expect(encryptedModels.data[1].email).toHaveProperty('c')
    expect(encryptedModels.data[1].address).toHaveProperty('c')
    expect(encryptedModels.data[1].age).toHaveProperty('c')
    expect(encryptedModels.data[1].score).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))

    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)
})

describe('Encryption with lock context', () => {
  it('should encrypt and decrypt number with lock context', async () => {
    const userJwt = process.env.USER_JWT

    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

    const lc = new LockContext()
    const lockContext = await lc.identify(userJwt)

    if (lockContext.failure) {
      throw new Error(`[protect]: ${lockContext.failure.message}`)
    }

    const age = 42

    const ciphertext = await protectClient
      .encrypt(age, {
        column: users.age,
        table: users,
      })
      .withLockContext(lockContext.data)

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('c')

    const plaintext = await protectClient
      .decrypt(ciphertext.data)
      .withLockContext(lockContext.data)

    if (plaintext.failure) {
      throw new Error(`[protect]: ${plaintext.failure.message}`)
    }

    expect(plaintext.data).toEqual(age)
  }, 30000)

  it('should encrypt model with lock context', async () => {
    const userJwt = process.env.USER_JWT

    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

    const lc = new LockContext()
    const lockContext = await lc.identify(userJwt)

    if (lockContext.failure) {
      throw new Error(`[protect]: ${lockContext.failure.message}`)
    }

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      age: 30,
      score: 95,
    }

    const encryptedModel = await protectClient
      .encryptModel(decryptedModel, users)
      .withLockContext(lockContext.data)

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.age).toHaveProperty('c')
    expect(encryptedModel.data.score).toHaveProperty('c')

    const decryptedResult = await protectClient
      .decryptModel(encryptedModel.data)
      .withLockContext(lockContext.data)

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should bulk encrypt numbers with lock context', async () => {
    const userJwt = process.env.USER_JWT

    if (!userJwt) {
      console.log('Skipping lock context test - no USER_JWT provided')
      return
    }

    const lc = new LockContext()
    const lockContext = await lc.identify(userJwt)

    if (lockContext.failure) {
      throw new Error(`[protect]: ${lockContext.failure.message}`)
    }

    const intPayloads = [
      { id: 'user1', plaintext: 25 },
      { id: 'user2', plaintext: 30 },
    ]

    const encryptedData = await protectClient
      .bulkEncrypt(intPayloads, {
        column: users.age,
        table: users,
      })
      .withLockContext(lockContext.data)

    if (encryptedData.failure) {
      throw new Error(`[protect]: ${encryptedData.failure.message}`)
    }

    // Verify structure
    expect(encryptedData.data).toHaveLength(2)
    expect(encryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(encryptedData.data[0]).toHaveProperty('data')
    expect(encryptedData.data[0].data).toHaveProperty('c')
    expect(encryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(encryptedData.data[1]).toHaveProperty('data')
    expect(encryptedData.data[1].data).toHaveProperty('c')

    // Decrypt with lock context
    const decryptedData = await protectClient
      .bulkDecrypt(encryptedData.data)
      .withLockContext(lockContext.data)

    if (decryptedData.failure) {
      throw new Error(`[protect]: ${decryptedData.failure.message}`)
    }

    // Verify decrypted data
    expect(decryptedData.data).toHaveLength(2)
    expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(decryptedData.data[0]).toHaveProperty('data', 25)
    expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(decryptedData.data[1]).toHaveProperty('data', 30)
  }, 30000)
})

describe('Nested object encryption', () => {
  it('should encrypt and decrypt nested number objects', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      metadata: {
        count: 100,
        level: 5,
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.metadata?.count).toHaveProperty('c')
    expect(encryptedModel.data.metadata?.level).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle null values in nested objects with number fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel: User = {
      id: '2',
      email: 'test2@example.com',
      metadata: {
        count: undefined,
        level: undefined,
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify null fields are preserved
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.metadata?.count).toBeUndefined()
    expect(encryptedModel.data.metadata?.level).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle undefined values in nested objects with number fields', async () => {
    const protectClient = await Encryption({ schemas: [users] })

    const decryptedModel = {
      id: '3',
      email: 'test3@example.com',
      metadata: {
        count: undefined,
        level: undefined,
      },
    }

    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify undefined fields are preserved
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.metadata?.count).toBeUndefined()
    expect(encryptedModel.data.metadata?.level).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)
})

describe('encryptQuery for numbers', () => {
  it('should create encrypted query for number fields', async () => {
    const result = await protectClient.encryptQuery([
      { value: 25, column: users.age, table: users, queryType: 'equality' },
      { value: 100, column: users.score, table: users, queryType: 'equality' },
    ])

    if (result.failure) {
      throw new Error(`[protect]: ${result.failure.message}`)
    }

    expect(result.data).toHaveLength(2)
    expect(result.data[0]).toHaveProperty('v', 2)
    expect(result.data[1]).toHaveProperty('v', 2)
  }, 30000)
})

describe('Performance tests', () => {
  it('should handle large numbers of numbers efficiently', async () => {
    const largeNumArray = Array.from({ length: 100 }, (_, i) => ({
      id: i,
      data: {
        age: i + 18, // Ages 18-117
        score: (i % 100) + 1, // Scores 1-100
      },
    }))

    const numPayloads = largeNumArray.map((item, index) => ({
      id: `user${index}`,
      plaintext: item.data.age,
    }))

    const encryptedData = await protectClient.bulkEncrypt(numPayloads, {
      column: users.age,
      table: users,
    })

    if (encryptedData.failure) {
      throw new Error(`[protect]: ${encryptedData.failure.message}`)
    }

    // Verify structure
    expect(encryptedData.data).toHaveLength(100)

    // Decrypt the data
    const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

    if (decryptedData.failure) {
      throw new Error(`[protect]: ${decryptedData.failure.message}`)
    }

    // Verify all data is preserved
    expect(decryptedData.data).toHaveLength(100)

    for (let i = 0; i < 100; i++) {
      expect(decryptedData.data[i].id).toBe(`user${i}`)
      expect(decryptedData.data[i].data).toEqual(largeNumArray[i].data.age)
    }
  }, 60000)
})

describe('Advanced scenarios', () => {
  it('should handle boundary values', async () => {
    const boundaryValues = [
      Number.MIN_SAFE_INTEGER,
      -2147483648, // Min 32-bit signed integer
      -1,
      0,
      1,
      2147483647, // Max 32-bit signed integer
      Number.MAX_SAFE_INTEGER,
    ]

    for (const value of boundaryValues) {
      const ciphertext = await protectClient.encrypt(value, {
        column: users.age,
        table: users,
      })

      if (ciphertext.failure) {
        throw new Error(`[protect]: ${ciphertext.failure.message}`)
      }

      // Verify encrypted field
      expect(ciphertext.data).toHaveProperty('c')

      const plaintext = await protectClient.decrypt(ciphertext.data)

      expect(plaintext).toEqual({
        data: value,
      })
    }
  }, 30000)
})

const invalidPlaintexts = [
  '400',
  'aaa',
  '100a',
  '73.51',
  {},
  [],
  [123],
  { num: 123 },
]

describe('Invalid or uncoercable values', () => {
  test.each(invalidPlaintexts)(
    'should fail to encrypt',
    async (input) => {
      const result = await protectClient.encrypt(input, {
        column: users.age,
        table: users,
      })

      expect(result.failure).toBeDefined()
      expect(result.failure?.message).toContain('Cannot convert')
    },
    30000,
  )
})
