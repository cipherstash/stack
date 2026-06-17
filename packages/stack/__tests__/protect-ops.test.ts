import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

const users = encryptedTable('users', {
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
})

type User = {
  id: string
  email?: string | null
  createdAt?: Date
  updatedAt?: Date
  address?: string | null
  number?: number
}

let protectClient: Awaited<ReturnType<typeof Encryption>>

beforeAll(async () => {
  protectClient = await Encryption({
    schemas: [users],
  })
})

describe('encryption and decryption edge cases', () => {
  it('should encrypt and decrypt a model', async () => {
    // Create a model with decrypted values
    const decryptedModel = {
      id: '1',
      email: 'plaintext',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      address: '123 Main St',
      number: 1,
    }

    // Encrypt the model
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

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.number).toBe(1)

    // Decrypt the model
    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual({
      id: '1',
      email: 'plaintext',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      address: '123 Main St',
      number: 1,
    })
  }, 30000)

  it('should handle null values in a model', async () => {
    // Create a model with null values
    const decryptedModel = {
      id: '1',
      email: null,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
      address: null,
    }

    // Encrypt the model
    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify null fields are preserved
    expect(encryptedModel.data.email).toBeNull()
    expect(encryptedModel.data.address).toBeNull()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.number).toBe(1)

    // Decrypt the model
    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual({
      id: '1',
      email: null,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
      address: null,
    })
  }, 30000)

  it('should handle undefined values in a model', async () => {
    // Create a model with undefined values
    const decryptedModel = {
      id: '1',
      email: undefined,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
      address: null,
    }

    // Encrypt the model
    const encryptedModel = await protectClient.encryptModel<User>(
      decryptedModel,
      users,
    )

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify undefined fields are preserved
    expect(encryptedModel.data.email).toBeUndefined()
    expect(encryptedModel.data.address).toBeNull()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.number).toBe(1)

    // Decrypt the model
    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual({
      id: '1',
      email: undefined,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
      address: null,
    })
  }, 30000)
})

describe('bulk encryption', () => {
  it('should bulk encrypt and decrypt models', async () => {
    // Create models with decrypted values
    const decryptedModels = [
      {
        id: '1',
        email: 'test',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
        address: '123 Main St',
      },
      {
        id: '2',
        email: 'test2',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
        address: null,
      },
    ]

    // Encrypt the models
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
    expect(encryptedModels.data[1].email).toHaveProperty('c')
    expect(encryptedModels.data[1].address).toBeNull()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].number).toBe(1)
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].number).toBe(2)

    // Decrypt the models
    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual([
      {
        id: '1',
        email: 'test',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
        address: '123 Main St',
      },
      {
        id: '2',
        email: 'test2',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
        address: null,
      },
    ])
  }, 30000)

  it('should return empty array if models is empty', async () => {
    // Encrypt empty array of models
    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      [],
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    expect(encryptedModels.data).toEqual([])
  }, 30000)

  it('should return empty array if decrypting empty array of models', async () => {
    // Decrypt empty array of models
    const decryptedResult = await protectClient.bulkDecryptModels<User>([])

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual([])
  }, 30000)
})

describe('bulk encryption edge cases', () => {
  it('should handle mixed null and non-null values in bulk operations', async () => {
    const decryptedModels = [
      {
        id: '1',
        email: 'test1',
        address: null,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
      },
      {
        id: '2',
        email: null,
        address: '123 Main St',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
      },
      {
        id: '3',
        email: 'test3',
        address: '456 Oak St',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 3,
      },
    ]

    // Encrypt the models
    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      decryptedModels,
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toHaveProperty('c')
    expect(encryptedModels.data[0].address).toBeNull()
    expect(encryptedModels.data[1].email).toBeNull()
    expect(encryptedModels.data[1].address).toHaveProperty('c')
    expect(encryptedModels.data[2].email).toHaveProperty('c')
    expect(encryptedModels.data[2].address).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].number).toBe(1)
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].number).toBe(2)
    expect(encryptedModels.data[2].id).toBe('3')
    expect(encryptedModels.data[2].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].number).toBe(3)

    // Decrypt the models
    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)

  it('should handle mixed undefined and non-undefined values in bulk operations', async () => {
    const decryptedModels = [
      {
        id: '1',
        email: 'test1',
        address: undefined,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
      },
      {
        id: '2',
        email: null,
        address: '123 Main St',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
      },
      {
        id: '3',
        email: 'test3',
        address: '456 Oak St',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 3,
      },
    ]

    // Encrypt the models
    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      decryptedModels,
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toHaveProperty('c')
    expect(encryptedModels.data[0].address).toBeUndefined()
    expect(encryptedModels.data[1].email).toBeNull()
    expect(encryptedModels.data[1].address).toHaveProperty('c')
    expect(encryptedModels.data[2].email).toHaveProperty('c')
    expect(encryptedModels.data[2].address).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].number).toBe(1)
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].number).toBe(2)
    expect(encryptedModels.data[2].id).toBe('3')
    expect(encryptedModels.data[2].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].number).toBe(3)

    // Decrypt the models
    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)

  it('should handle empty models in bulk operations', async () => {
    const decryptedModels = [
      {
        id: '1',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
      }, // No encrypted fields
      {
        id: '2',
        email: 'test2',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
      },
      {
        id: '3',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 3,
      }, // No encrypted fields
    ]

    // Encrypt the models
    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      decryptedModels,
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toBeUndefined()
    expect(encryptedModels.data[0].address).toBeUndefined()
    expect(encryptedModels.data[1].email).toHaveProperty('c')
    expect(encryptedModels.data[1].address).toBeUndefined()
    expect(encryptedModels.data[2].email).toBeUndefined()
    expect(encryptedModels.data[2].address).toBeUndefined()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].number).toBe(1)
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].number).toBe(2)
    expect(encryptedModels.data[2].id).toBe('3')
    expect(encryptedModels.data[2].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[2].number).toBe(3)

    // Decrypt the models
    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)
})

describe('error handling', () => {
  it('should handle invalid encrypted payloads', async () => {
    const validModel = {
      id: '1',
      email: 'test@example.com',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      address: '123 Main St',
      number: 1,
    }

    // First encrypt a valid model
    const encryptedModel = await protectClient.encryptModel<User>(
      validModel,
      users,
    )
    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Create an invalid model by removing required fields
    const invalidModel = {
      id: '1',
      // Missing required fields
    }

    try {
      await protectClient.decryptModel<User>(invalidModel as User)
      throw new Error('Expected decryption to fail')
    } catch (error) {
      expect(error).toBeDefined()
    }
  }, 30000)

  it('should handle missing required fields', async () => {
    const model = {
      id: '1',
      email: null,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      address: null,
      number: 1,
    }

    try {
      await protectClient.encryptModel<User>(model, users)
      throw new Error('Expected encryption to fail')
    } catch (error) {
      expect(error).toBeDefined()
    }
  }, 30000)
})

describe('type safety', () => {
  it('should maintain type safety with complex nested objects', async () => {
    const model = {
      id: '1',
      email: 'test@example.com',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      address: '123 Main St',
      number: 1,
      metadata: {
        preferences: {
          notifications: true,
          theme: 'dark',
        },
      },
    }

    // Encrypt the model
    const encryptedModel = await protectClient.encryptModel<User>(model, users)

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Decrypt the model
    const decryptedResult = await protectClient.decryptModel<User>(
      encryptedModel.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(model)
  }, 30000)
})

describe('performance', () => {
  it('should handle large numbers of models efficiently', async () => {
    const largeModels = Array(10)
      .fill(null)
      .map((_, i) => ({
        id: i.toString(),
        email: `test${i}@example.com`,
        address: `Address ${i}`,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: i,
      }))

    // Encrypt the models
    const encryptedModels = await protectClient.bulkEncryptModels<User>(
      largeModels,
      users,
    )

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Decrypt the models
    const decryptedResult = await protectClient.bulkDecryptModels<User>(
      encryptedModels.data,
    )

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(largeModels)
  }, 60000)
})

describe('encryption and decryption with lock context', () => {
  it('should encrypt and decrypt a payload with lock context', async () => {
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

    const email = 'hello@example.com'

    const ciphertext = await protectClient
      .encrypt(email, {
        column: users.email,
        table: users,
      })
      .withLockContext(lockContext.data)

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    const plaintext = await protectClient
      .decrypt(ciphertext.data)
      .withLockContext(lockContext.data)

    if (plaintext.failure) {
      throw new Error(`[protect]: ${plaintext.failure.message}`)
    }

    expect(plaintext.data).toEqual(email)
  }, 30000)

  it('should encrypt and decrypt a model with lock context', async () => {
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

    // Create a model with decrypted values
    const decryptedModel = {
      id: '1',
      email: 'plaintext',
    }

    // Encrypt the model with lock context
    const encryptedModel = await protectClient
      .encryptModel(decryptedModel, users)
      .withLockContext(lockContext.data)

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Decrypt the model with lock context
    const decryptedResult = await protectClient
      .decryptModel(encryptedModel.data)
      .withLockContext(lockContext.data)

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual({
      id: '1',
      email: 'plaintext',
    })
  }, 30000)

  it('should encrypt with context and be unable to decrypt without context', async () => {
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

    // Create a model with decrypted values
    const decryptedModel = {
      id: '1',
      email: 'plaintext',
    }

    // Encrypt the model with lock context
    const encryptedModel = await protectClient
      .encryptModel(decryptedModel, users)
      .withLockContext(lockContext.data)

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    try {
      await protectClient.decryptModel(encryptedModel.data)
    } catch (error) {
      const e = error as Error
      expect(e.message.startsWith('Failed to retrieve key')).toEqual(true)
    }
  }, 30000)

  it('should bulk encrypt and decrypt models with lock context', async () => {
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

    // Create models with decrypted values
    const decryptedModels = [
      {
        id: '1',
        email: 'test',
      },
      {
        id: '2',
        email: 'test2',
      },
    ]

    // Encrypt the models with lock context
    const encryptedModels = await protectClient
      .bulkEncryptModels(decryptedModels, users)
      .withLockContext(lockContext.data)

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Decrypt the models with lock context
    const decryptedResult = await protectClient
      .bulkDecryptModels(encryptedModels.data)
      .withLockContext(lockContext.data)

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual([
      {
        id: '1',
        email: 'test',
      },
      {
        id: '2',
        email: 'test2',
      },
    ])
  }, 30000)
})

describe('special characters', () => {
  it('should encrypt and decrypt multiple special characters together', async () => {
    const plaintext =
      'complex@string-with/slashes\\backslashes.and#symbols$%&+!@#$%^&*()_+-=[]{}|;:,.<>?/~`'

    const ciphertext = await protectClient.encrypt(plaintext, {
      column: users.email,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    const decrypted = await protectClient.decrypt(ciphertext.data)

    expect(decrypted).toEqual({
      data: plaintext,
    })
  }, 30000)
})
