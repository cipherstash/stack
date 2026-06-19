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
