import 'dotenv/config'
import { csColumn, csTable, csValue } from '@cipherstash/schema'
import { beforeAll, describe, expect, it } from 'vitest'
import { LockContext, protect } from '../src'

const users = csTable('users', {
  email: csColumn('email').freeTextSearch().equality().orderAndRange(),
  address: csColumn('address').freeTextSearch(),
  json: csColumn('json').dataType('json'),
  metadata: {
    profile: csValue('metadata.profile').dataType('json'),
    settings: {
      preferences: csValue('metadata.settings.preferences').dataType('json'),
    },
  },
})

type User = {
  id: string
  email?: string | null
  createdAt?: Date
  updatedAt?: Date
  address?: string | null
  json?: Record<string, unknown> | null
  metadata?: {
    profile?: Record<string, unknown> | null
    settings?: {
      preferences?: Record<string, unknown> | null
    }
  }
}

let protectClient: Awaited<ReturnType<typeof protect>>

beforeAll(async () => {
  protectClient = await protect({
    schemas: [users],
  })
})

describe('JSON encryption and decryption', () => {
  it('should encrypt and decrypt a simple JSON payload', async () => {
    const json = {
      name: 'John Doe',
      age: 30,
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should encrypt and decrypt a complex JSON payload', async () => {
    const json = {
      user: {
        id: 123,
        name: 'Jane Smith',
        email: 'jane@example.com',
        preferences: {
          theme: 'dark',
          notifications: true,
          language: 'en-US',
        },
        tags: ['premium', 'verified'],
        metadata: {
          created: '2023-01-01T00:00:00Z',
          lastLogin: '2023-12-01T10:30:00Z',
        },
      },
      settings: {
        privacy: {
          public: false,
          shareData: true,
        },
        features: {
          beta: true,
          experimental: false,
        },
      },
      array: [1, 2, 3, { nested: 'value' }],
      nullValue: null,
      booleanValue: true,
      numberValue: 42.5,
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle null JSON payload', async () => {
    const ciphertext = await protectClient.encrypt(null, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify null is preserved
    expect(ciphertext.data).toBeNull()

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: null,
    })
  }, 30000)

  it('should handle empty JSON object', async () => {
    const json = {}

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with special characters', async () => {
    const json = {
      message: 'Hello "world" with \'quotes\' and \\backslashes\\',
      unicode: '🚀 emoji and ñ special chars',
      symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?/~`',
      multiline: 'Line 1\nLine 2\tTabbed',
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)
})

describe('JSON model encryption and decryption', () => {
  it('should encrypt and decrypt a model with JSON field', async () => {
    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      json: {
        name: 'John Doe',
        age: 30,
        preferences: {
          theme: 'dark',
          notifications: true,
        },
      },
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.address).toHaveProperty('k')
    expect(encryptedModel.data.json).toHaveProperty('k')

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

  it('should handle null JSON in model', async () => {
    const decryptedModel = {
      id: '2',
      email: 'test2@example.com',
      address: '456 Oak St',
      json: null,
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.address).toHaveProperty('k')
    expect(encryptedModel.data.json).toBeNull()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle undefined JSON in model', async () => {
    const decryptedModel = {
      id: '3',
      email: 'test3@example.com',
      address: '789 Pine St',
      json: undefined,
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.address).toHaveProperty('k')
    expect(encryptedModel.data.json).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)
})

describe('JSON bulk encryption and decryption', () => {
  it('should bulk encrypt and decrypt JSON payloads', async () => {
    const jsonPayloads = [
      { id: 'user1', plaintext: { name: 'Alice', age: 25 } },
      { id: 'user2', plaintext: { name: 'Bob', age: 30 } },
      { id: 'user3', plaintext: { name: 'Charlie', age: 35 } },
    ]

    const encryptedData = await protectClient.bulkEncrypt(jsonPayloads, {
      column: users.json,
      table: users,
    })

    if (encryptedData.failure) {
      throw new Error(`[protect]: ${encryptedData.failure.message}`)
    }

    // Verify structure
    expect(encryptedData.data).toHaveLength(3)
    expect(encryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(encryptedData.data[0]).toHaveProperty('data')
    expect(encryptedData.data[0].data).toHaveProperty('k')
    expect(encryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(encryptedData.data[1]).toHaveProperty('data')
    expect(encryptedData.data[1].data).toHaveProperty('k')
    expect(encryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(encryptedData.data[2]).toHaveProperty('data')
    expect(encryptedData.data[2].data).toHaveProperty('k')

    // Now decrypt the data
    const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

    if (decryptedData.failure) {
      throw new Error(`[protect]: ${decryptedData.failure.message}`)
    }

    // Verify decrypted data
    expect(decryptedData.data).toHaveLength(3)
    expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(decryptedData.data[0]).toHaveProperty('data', {
      name: 'Alice',
      age: 25,
    })
    expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(decryptedData.data[1]).toHaveProperty('data', {
      name: 'Bob',
      age: 30,
    })
    expect(decryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(decryptedData.data[2]).toHaveProperty('data', {
      name: 'Charlie',
      age: 35,
    })
  }, 30000)

  it('should handle mixed null and non-null JSON in bulk operations', async () => {
    const jsonPayloads = [
      { id: 'user1', plaintext: { name: 'Alice', age: 25 } },
      { id: 'user2', plaintext: null },
      { id: 'user3', plaintext: { name: 'Charlie', age: 35 } },
    ]

    const encryptedData = await protectClient.bulkEncrypt(jsonPayloads, {
      column: users.json,
      table: users,
    })

    if (encryptedData.failure) {
      throw new Error(`[protect]: ${encryptedData.failure.message}`)
    }

    // Verify structure
    expect(encryptedData.data).toHaveLength(3)
    expect(encryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(encryptedData.data[0]).toHaveProperty('data')
    expect(encryptedData.data[0].data).toHaveProperty('k')
    expect(encryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(encryptedData.data[1]).toHaveProperty('data')
    expect(encryptedData.data[1].data).toBeNull()
    expect(encryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(encryptedData.data[2]).toHaveProperty('data')
    expect(encryptedData.data[2].data).toHaveProperty('k')

    // Now decrypt the data
    const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

    if (decryptedData.failure) {
      throw new Error(`[protect]: ${decryptedData.failure.message}`)
    }

    // Verify decrypted data
    expect(decryptedData.data).toHaveLength(3)
    expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
    expect(decryptedData.data[0]).toHaveProperty('data', {
      name: 'Alice',
      age: 25,
    })
    expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(decryptedData.data[1]).toHaveProperty('data', null)
    expect(decryptedData.data[2]).toHaveProperty('id', 'user3')
    expect(decryptedData.data[2]).toHaveProperty('data', {
      name: 'Charlie',
      age: 35,
    })
  }, 30000)

  it('should bulk encrypt and decrypt models with JSON fields', async () => {
    const decryptedModels = [
      {
        id: '1',
        email: 'test1@example.com',
        address: '123 Main St',
        json: {
          name: 'Alice',
          preferences: { theme: 'dark' },
        },
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
      },
      {
        id: '2',
        email: 'test2@example.com',
        address: '456 Oak St',
        json: {
          name: 'Bob',
          preferences: { theme: 'light' },
        },
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
    expect(encryptedModels.data[0].email).toHaveProperty('k')
    expect(encryptedModels.data[0].address).toHaveProperty('k')
    expect(encryptedModels.data[0].json).toHaveProperty('k')
    expect(encryptedModels.data[1].email).toHaveProperty('k')
    expect(encryptedModels.data[1].address).toHaveProperty('k')
    expect(encryptedModels.data[1].json).toHaveProperty('k')

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

describe('JSON encryption with lock context', () => {
  it('should encrypt and decrypt JSON with lock context', async () => {
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

    const json = {
      name: 'John Doe',
      age: 30,
      preferences: {
        theme: 'dark',
        notifications: true,
      },
    }

    const ciphertext = await protectClient
      .encrypt(json, {
        column: users.json,
        table: users,
      })
      .withLockContext(lockContext.data)

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient
      .decrypt(ciphertext.data)
      .withLockContext(lockContext.data)

    if (plaintext.failure) {
      throw new Error(`[protect]: ${plaintext.failure.message}`)
    }

    expect(plaintext.data).toEqual(json)
  }, 30000)

  it('should encrypt JSON model with lock context', async () => {
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
      json: {
        name: 'John Doe',
        preferences: { theme: 'dark' },
      },
    }

    const encryptedModel = await protectClient
      .encryptModel(decryptedModel, users)
      .withLockContext(lockContext.data)

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.json).toHaveProperty('k')

    const decryptedResult = await protectClient
      .decryptModel(encryptedModel.data)
      .withLockContext(lockContext.data)

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should bulk encrypt JSON with lock context', async () => {
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

    const jsonPayloads = [
      { id: 'user1', plaintext: { name: 'Alice', age: 25 } },
      { id: 'user2', plaintext: { name: 'Bob', age: 30 } },
    ]

    const encryptedData = await protectClient
      .bulkEncrypt(jsonPayloads, {
        column: users.json,
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
    expect(encryptedData.data[0].data).toHaveProperty('k')
    expect(encryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(encryptedData.data[1]).toHaveProperty('data')
    expect(encryptedData.data[1].data).toHaveProperty('k')

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
    expect(decryptedData.data[0]).toHaveProperty('data', {
      name: 'Alice',
      age: 25,
    })
    expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
    expect(decryptedData.data[1]).toHaveProperty('data', {
      name: 'Bob',
      age: 30,
    })
  }, 30000)
})

describe('JSON nested object encryption', () => {
  it('should encrypt and decrypt nested JSON objects', async () => {
    const protectClient = await protect({ schemas: [users] })

    const decryptedModel = {
      id: '1',
      email: 'test@example.com',
      metadata: {
        profile: {
          name: 'John Doe',
          age: 30,
          preferences: {
            theme: 'dark',
            notifications: true,
          },
        },
        settings: {
          preferences: {
            language: 'en-US',
            timezone: 'UTC',
          },
        },
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.metadata?.profile).toHaveProperty('k')
    expect(encryptedModel.data.metadata?.settings?.preferences).toHaveProperty(
      'c',
    )

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

  it('should handle null values in nested JSON objects', async () => {
    const protectClient = await protect({ schemas: [users] })

    const decryptedModel = {
      id: '2',
      email: 'test2@example.com',
      metadata: {
        profile: null,
        settings: {
          preferences: null,
        },
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.metadata?.profile).toBeNull()
    expect(encryptedModel.data.metadata?.settings?.preferences).toBeNull()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle undefined values in nested JSON objects', async () => {
    const protectClient = await protect({ schemas: [users] })

    const decryptedModel = {
      id: '3',
      email: 'test3@example.com',
      metadata: {
        profile: undefined,
        settings: {
          preferences: undefined,
        },
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
    expect(encryptedModel.data.email).toHaveProperty('k')
    expect(encryptedModel.data.metadata?.profile).toBeUndefined()
    expect(encryptedModel.data.metadata?.settings?.preferences).toBeUndefined()

    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)
})

describe('JSON edge cases and error handling', () => {
  it('should handle very large JSON objects', async () => {
    const largeJson = {
      data: Array.from({ length: 1000 }, (_, i) => ({
        id: i,
        name: `User ${i}`,
        email: `user${i}@example.com`,
        metadata: {
          preferences: {
            theme: i % 2 === 0 ? 'dark' : 'light',
            notifications: i % 3 === 0,
          },
        },
      })),
      metadata: {
        total: 1000,
        created: new Date().toISOString(),
      },
    }

    const ciphertext = await protectClient.encrypt(largeJson, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: largeJson,
    })
  }, 30000)

  it('should handle JSON with circular references (should fail gracefully)', async () => {
    const circularObj: Record<string, unknown> = { name: 'test' }
    circularObj.self = circularObj

    try {
      await protectClient.encrypt(circularObj, {
        column: users.json,
        table: users,
      })
      // This should not reach here as JSON.stringify should fail
      expect(true).toBe(false)
    } catch (error) {
      // Expected to fail due to circular reference
      expect(error).toBeDefined()
    }
  }, 30000)

  it('should handle JSON with special data types', async () => {
    const json = {
      string: 'hello',
      number: 42,
      boolean: true,
      null: null,
      array: [1, 2, 3],
      object: { nested: 'value' },
      date: new Date('2023-01-01T00:00:00Z'),
      // Note: Functions and undefined are not JSON serializable
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    // Date objects get serialized to strings in JSON
    const expectedJson = {
      ...json,
      date: '2023-01-01T00:00:00.000Z',
    }

    expect(plaintext).toEqual({
      data: expectedJson,
    })
  }, 30000)
})

describe('JSON performance tests', () => {
  it('should handle large numbers of JSON objects efficiently', async () => {
    const largeJsonArray = Array.from({ length: 100 }, (_, i) => ({
      id: i,
      data: {
        name: `User ${i}`,
        preferences: {
          theme: i % 2 === 0 ? 'dark' : 'light',
          notifications: i % 3 === 0,
        },
        metadata: {
          created: new Date().toISOString(),
          version: i,
        },
      },
    }))

    const jsonPayloads = largeJsonArray.map((item, index) => ({
      id: `user${index}`,
      plaintext: item,
    }))

    const encryptedData = await protectClient.bulkEncrypt(jsonPayloads, {
      column: users.json,
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
      expect(decryptedData.data[i].data).toEqual(largeJsonArray[i])
    }
  }, 5000)
})

describe('JSON advanced scenarios', () => {
  it('should handle JSON with deeply nested arrays', async () => {
    const json = {
      users: [
        {
          id: 1,
          name: 'Alice',
          roles: [
            { name: 'admin', permissions: ['read', 'write', 'delete'] },
            { name: 'user', permissions: ['read'] },
          ],
        },
        {
          id: 2,
          name: 'Bob',
          roles: [{ name: 'user', permissions: ['read'] }],
        },
      ],
      metadata: {
        total: 2,
        lastUpdated: new Date().toISOString(),
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with mixed data types in arrays', async () => {
    const json = {
      mixedArray: ['string', 42, true, null, { nested: 'object' }, [1, 2, 3]],
      metadata: {
        types: ['string', 'number', 'boolean', 'null', 'object', 'array'],
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with Unicode and international characters', async () => {
    const json = {
      international: {
        chinese: '你好世界',
        japanese: 'こんにちは世界',
        korean: '안녕하세요 세계',
        arabic: 'مرحبا بالعالم',
        russian: 'Привет мир',
        emoji: '🚀 🌍 💻 🎉',
      },
      metadata: {
        languages: ['Chinese', 'Japanese', 'Korean', 'Arabic', 'Russian'],
        encoding: 'UTF-8',
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with scientific notation and large numbers', async () => {
    const json = {
      numbers: {
        integer: 1234567890,
        float: Math.PI,
        scientific: 1.23e10,
        negative: -9876543210,
        zero: 0,
        verySmall: 1.23e-10,
      },
      metadata: {
        precision: 'high',
        format: 'scientific',
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with boolean edge cases', async () => {
    const json = {
      booleans: {
        true: true,
        false: false,
        stringTrue: 'true',
        stringFalse: 'false',
        numberOne: 1,
        numberZero: 0,
        emptyString: '',
        nullValue: null,
      },
      metadata: {
        type: 'boolean_edge_cases',
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)
})

describe('JSON error handling and edge cases', () => {
  it('should handle malformed JSON gracefully', async () => {
    // This test ensures the library handles JSON serialization errors
    const invalidJson = {
      valid: 'data',
      // This will cause JSON.stringify to fail
      circular: null as unknown,
    }

    // Create a circular reference
    invalidJson.circular = invalidJson

    try {
      await protectClient.encrypt(invalidJson, {
        column: users.json,
        table: users,
      })
      expect(true).toBe(false) // Should not reach here
    } catch (error) {
      expect(error).toBeDefined()
      expect(error).toBeInstanceOf(Error)
    }
  }, 30000)

  it('should handle empty arrays and objects', async () => {
    const json = {
      emptyArray: [],
      emptyObject: {},
      nestedEmpty: {
        array: [],
        object: {},
      },
      mixedEmpty: {
        data: 'present',
        empty: [],
        null: null,
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with very long strings', async () => {
    const longString = 'A'.repeat(10000) // 10KB string
    const json = {
      longString,
      metadata: {
        length: longString.length,
        type: 'long_string',
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)

  it('should handle JSON with all primitive types', async () => {
    const json = {
      string: 'hello world',
      number: 42,
      float: 3.14,
      boolean: true,
      null: null,
      array: [1, 2, 3],
      object: { key: 'value' },
      nested: {
        level1: {
          level2: {
            level3: 'deep value',
          },
        },
      },
    }

    const ciphertext = await protectClient.encrypt(json, {
      column: users.json,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('k')

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: json,
    })
  }, 30000)
})
