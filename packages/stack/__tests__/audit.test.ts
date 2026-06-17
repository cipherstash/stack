import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'

const users = encryptedTable('users', {
  auditable: encryptedColumn('auditable'),
  email: encryptedColumn('email').freeTextSearch().equality().orderAndRange(),
  address: encryptedColumn('address').freeTextSearch(),
})

type User = {
  id: string
  email?: string | null
  address?: string | null
  auditable?: string | null
  createdAt?: Date
  updatedAt?: Date
  number?: number
}

let protectClient: Awaited<ReturnType<typeof Encryption>>

beforeAll(async () => {
  protectClient = await Encryption({
    schemas: [users],
  })
})

describe('encryption and decryption with audit', () => {
  it('should encrypt and decrypt a payload with audit metadata', async () => {
    const email = 'very_secret_data'

    const ciphertext = await protectClient
      .encrypt(email, {
        column: users.auditable,
        table: users,
      })
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'encrypt',
        },
      })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('c')

    const plaintext = await protectClient.decrypt(ciphertext.data).audit({
      metadata: {
        sub: 'cj@cjb.io',
        type: 'decrypt',
      },
    })

    expect(plaintext).toEqual({
      data: email,
    })
  }, 30000)

  it('should encrypt and decrypt a model with audit metadata', async () => {
    // Create a model with decrypted values
    const decryptedModel: User = {
      id: '1',
      email: 'test@example.com',
      address: '123 Main St',
      auditable: 'sensitive_data',
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
    }

    // Encrypt the model with audit
    const encryptedModel = await protectClient
      .encryptModel<User>(decryptedModel, users)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'encrypt_model',
        },
      })

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify encrypted fields
    expect(encryptedModel.data.email).toHaveProperty('c')
    expect(encryptedModel.data.address).toHaveProperty('c')
    expect(encryptedModel.data.auditable).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.number).toBe(1)

    // Decrypt the model with audit
    const decryptedResult = await protectClient
      .decryptModel<User>(encryptedModel.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'decrypt_model',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should handle null values in a model with audit metadata', async () => {
    // Create a model with null values
    const decryptedModel: User = {
      id: '1',
      email: null,
      address: null,
      auditable: null,
      createdAt: new Date('2021-01-01'),
      updatedAt: new Date('2021-01-01'),
      number: 1,
    }

    // Encrypt the model with audit
    const encryptedModel = await protectClient
      .encryptModel<User>(decryptedModel, users)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'encrypt_model_nulls',
        },
      })

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Verify null fields are preserved
    expect(encryptedModel.data.email).toBeNull()
    expect(encryptedModel.data.address).toBeNull()
    expect(encryptedModel.data.auditable).toBeNull()

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModel.data.id).toBe('1')
    expect(encryptedModel.data.createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModel.data.number).toBe(1)

    // Decrypt the model with audit
    const decryptedResult = await protectClient
      .decryptModel<User>(encryptedModel.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'decrypt_model_nulls',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)
})

describe('bulk encryption with audit', () => {
  it('should bulk encrypt and decrypt models with audit metadata', async () => {
    // Create models with decrypted values
    const decryptedModels: User[] = [
      {
        id: '1',
        email: 'test1@example.com',
        address: '123 Main St',
        auditable: 'sensitive_data_1',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
      },
      {
        id: '2',
        email: 'test2@example.com',
        address: '456 Oak St',
        auditable: 'sensitive_data_2',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
      },
    ]

    // Encrypt the models with audit
    const encryptedModels = await protectClient
      .bulkEncryptModels<User>(decryptedModels, users)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_encrypt_models',
        },
      })

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toHaveProperty('c')
    expect(encryptedModels.data[0].address).toHaveProperty('c')
    expect(encryptedModels.data[0].auditable).toHaveProperty('c')
    expect(encryptedModels.data[1].email).toHaveProperty('c')
    expect(encryptedModels.data[1].address).toHaveProperty('c')
    expect(encryptedModels.data[1].auditable).toHaveProperty('c')

    // Verify non-encrypted fields remain unchanged
    expect(encryptedModels.data[0].id).toBe('1')
    expect(encryptedModels.data[0].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[0].number).toBe(1)
    expect(encryptedModels.data[1].id).toBe('2')
    expect(encryptedModels.data[1].createdAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].updatedAt).toEqual(new Date('2021-01-01'))
    expect(encryptedModels.data[1].number).toBe(2)

    // Decrypt the models with audit
    const decryptedResult = await protectClient
      .bulkDecryptModels<User>(encryptedModels.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_decrypt_models',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)

  it('should handle mixed null and non-null values in bulk operations with audit', async () => {
    const decryptedModels: User[] = [
      {
        id: '1',
        email: 'test1@example.com',
        address: null,
        auditable: 'sensitive_data_1',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 1,
      },
      {
        id: '2',
        email: null,
        address: '123 Main St',
        auditable: null,
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 2,
      },
      {
        id: '3',
        email: 'test3@example.com',
        address: '456 Oak St',
        auditable: 'sensitive_data_3',
        createdAt: new Date('2021-01-01'),
        updatedAt: new Date('2021-01-01'),
        number: 3,
      },
    ]

    // Encrypt the models with audit
    const encryptedModels = await protectClient
      .bulkEncryptModels<User>(decryptedModels, users)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_encrypt_mixed_nulls',
        },
      })

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Verify encrypted fields for each model
    expect(encryptedModels.data[0].email).toHaveProperty('c')
    expect(encryptedModels.data[0].address).toBeNull()
    expect(encryptedModels.data[0].auditable).toHaveProperty('c')
    expect(encryptedModels.data[1].email).toBeNull()
    expect(encryptedModels.data[1].address).toHaveProperty('c')
    expect(encryptedModels.data[1].auditable).toBeNull()
    expect(encryptedModels.data[2].email).toHaveProperty('c')
    expect(encryptedModels.data[2].address).toHaveProperty('c')
    expect(encryptedModels.data[2].auditable).toHaveProperty('c')

    // Decrypt the models with audit
    const decryptedResult = await protectClient
      .bulkDecryptModels<User>(decryptedModels)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_decrypt_mixed_nulls',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)

  it('should return empty array if models is empty with audit', async () => {
    // Encrypt empty array of models with audit
    const encryptedModels = await protectClient
      .bulkEncryptModels<User>([], users)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_encrypt_empty',
        },
      })

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    expect(encryptedModels.data).toEqual([])

    // Decrypt empty array of models with audit
    const decryptedResult = await protectClient
      .bulkDecryptModels<User>([])
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_decrypt_empty',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual([])
  }, 30000)
})

describe('audit with lock context', () => {
  it('should encrypt and decrypt a model with both audit and lock context', async () => {
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
    const decryptedModel: User = {
      id: '1',
      email: 'test@example.com',
      auditable: 'sensitive_with_context',
    }

    // Encrypt the model with both audit and lock context
    const encryptedModel = await protectClient
      .encryptModel(decryptedModel, users)
      .withLockContext(lockContext.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'encrypt_with_context',
        },
      })

    if (encryptedModel.failure) {
      throw new Error(`[protect]: ${encryptedModel.failure.message}`)
    }

    // Decrypt the model with both audit and lock context
    const decryptedResult = await protectClient
      .decryptModel(encryptedModel.data)
      .withLockContext(lockContext.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'decrypt_with_context',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModel)
  }, 30000)

  it('should bulk encrypt and decrypt models with both audit and lock context', async () => {
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
    const decryptedModels: User[] = [
      {
        id: '1',
        email: 'test1@example.com',
        auditable: 'bulk_sensitive_1',
      },
      {
        id: '2',
        email: 'test2@example.com',
        auditable: 'bulk_sensitive_2',
      },
    ]

    // Encrypt the models with both audit and lock context
    const encryptedModels = await protectClient
      .bulkEncryptModels(decryptedModels, users)
      .withLockContext(lockContext.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_encrypt_with_context',
        },
      })

    if (encryptedModels.failure) {
      throw new Error(`[protect]: ${encryptedModels.failure.message}`)
    }

    // Decrypt the models with both audit and lock context
    const decryptedResult = await protectClient
      .bulkDecryptModels(encryptedModels.data)
      .withLockContext(lockContext.data)
      .audit({
        metadata: {
          sub: 'cj@cjb.io',
          type: 'bulk_decrypt_with_context',
        },
      })

    if (decryptedResult.failure) {
      throw new Error(`[protect]: ${decryptedResult.failure.message}`)
    }

    expect(decryptedResult.data).toEqual(decryptedModels)
  }, 30000)
})
