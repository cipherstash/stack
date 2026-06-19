import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { LockContext } from '@/identity'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'
import type { Encrypted } from '@/types'

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

describe('bulk encryption and decryption', () => {
  describe('bulk encrypt', () => {
    it('should bulk encrypt an array of plaintexts with IDs', async () => {
      const plaintexts = [
        { id: 'user1', plaintext: 'alice@example.com' },
        { id: 'user2', plaintext: 'bob@example.com' },
        { id: 'user3', plaintext: 'charlie@example.com' },
      ]

      const encryptedData = await protectClient.bulkEncrypt(plaintexts, {
        column: users.email,
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
      expect(encryptedData.data[2]).toHaveProperty('id', 'user3')
      expect(encryptedData.data[2]).toHaveProperty('data')

      // Verify all encrypted values are different
      expect(encryptedData.data[0].data?.c).not.toBe(
        encryptedData.data[1].data?.c,
      )
      expect(encryptedData.data[1].data?.c).not.toBe(
        encryptedData.data[2].data?.c,
      )
      expect(encryptedData.data[0].data?.c).not.toBe(
        encryptedData.data[2].data?.c,
      )
    }, 30000)

    it('should bulk encrypt an array of plaintexts without IDs', async () => {
      const plaintexts = [
        { plaintext: 'alice@example.com' },
        { plaintext: 'bob@example.com' },
        { plaintext: 'charlie@example.com' },
      ]

      const encryptedData = await protectClient.bulkEncrypt(plaintexts, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      // Verify structure
      expect(encryptedData.data).toHaveLength(3)
      expect(encryptedData.data[0]).toHaveProperty('id', undefined)
      expect(encryptedData.data[0]).toHaveProperty('data')
      expect(encryptedData.data[0].data).toHaveProperty('c')
      expect(encryptedData.data[1]).toHaveProperty('id', undefined)
      expect(encryptedData.data[1]).toHaveProperty('data')
      expect(encryptedData.data[1].data).toHaveProperty('c')
      expect(encryptedData.data[2]).toHaveProperty('id', undefined)
      expect(encryptedData.data[2]).toHaveProperty('data')
      expect(encryptedData.data[2].data).toHaveProperty('c')
    }, 30000)

    it('should handle empty array in bulk encrypt', async () => {
      const plaintexts: Array<{ id?: string; plaintext: string }> = []

      const encryptedData = await protectClient.bulkEncrypt(plaintexts, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      expect(encryptedData.data).toHaveLength(0)
    }, 30000)
  })

  describe('bulk decrypt', () => {
    it('should bulk decrypt an array of encrypted payloads with IDs', async () => {
      // First encrypt some data
      const plaintexts = [
        { id: 'user1', plaintext: 'alice@example.com' },
        { id: 'user2', plaintext: 'bob@example.com' },
        { id: 'user3', plaintext: 'charlie@example.com' },
      ]

      const encryptedData = await protectClient.bulkEncrypt(plaintexts, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      // Now decrypt the data
      const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify structure
      expect(decryptedData.data).toHaveLength(3)
      expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
      expect(decryptedData.data[0]).toHaveProperty('data', 'alice@example.com')
      expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
      expect(decryptedData.data[1]).toHaveProperty('data', 'bob@example.com')
      expect(decryptedData.data[2]).toHaveProperty('id', 'user3')
      expect(decryptedData.data[2]).toHaveProperty(
        'data',
        'charlie@example.com',
      )
    }, 30000)

    it('should bulk decrypt an array of encrypted payloads without IDs', async () => {
      // First encrypt some data
      const plaintexts = [
        { plaintext: 'alice@example.com' },
        { plaintext: 'bob@example.com' },
        { plaintext: 'charlie@example.com' },
      ]

      const encryptedData = await protectClient.bulkEncrypt(plaintexts, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      // Now decrypt the data
      const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify structure
      expect(decryptedData.data).toHaveLength(3)
      expect(decryptedData.data[0]).toHaveProperty('id', undefined)
      expect(decryptedData.data[0]).toHaveProperty('data', 'alice@example.com')
      expect(decryptedData.data[1]).toHaveProperty('id', undefined)
      expect(decryptedData.data[1]).toHaveProperty('data', 'bob@example.com')
      expect(decryptedData.data[2]).toHaveProperty('id', undefined)
      expect(decryptedData.data[2]).toHaveProperty(
        'data',
        'charlie@example.com',
      )
    }, 30000)

    it('should handle empty array in bulk decrypt', async () => {
      const encryptedPayloads: Array<{ id?: string; data: Encrypted }> = []

      const decryptedData = await protectClient.bulkDecrypt(encryptedPayloads)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      expect(decryptedData.data).toHaveLength(0)
    }, 30000)
  })

  describe('bulk operations with lock context', () => {
    it('should bulk encrypt and decrypt with lock context', async () => {
      // This test requires a valid JWT token, so we'll skip it in CI
      // TODO: Add proper JWT token handling for CI
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

      const plaintexts = [
        { id: 'user1', plaintext: 'alice@example.com' },
        { id: 'user2', plaintext: 'bob@example.com' },
        { id: 'user3', plaintext: 'charlie@example.com' },
      ]

      // Encrypt with lock context
      const encryptedData = await protectClient
        .bulkEncrypt(plaintexts, {
          column: users.email,
          table: users,
        })
        .withLockContext(lockContext.data)

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

      // Decrypt with lock context
      const decryptedData = await protectClient
        .bulkDecrypt(encryptedData.data)
        .withLockContext(lockContext.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify decrypted data
      expect(decryptedData.data).toHaveLength(3)
      expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
      expect(decryptedData.data[0]).toHaveProperty('data', 'alice@example.com')
      expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
      expect(decryptedData.data[1]).toHaveProperty('data', 'bob@example.com')
      expect(decryptedData.data[2]).toHaveProperty('id', 'user3')
      expect(decryptedData.data[2]).toHaveProperty(
        'data',
        'charlie@example.com',
      )
    }, 30000)

    it('should decrypt mixed lock context payloads with specific lock context', async () => {
      const userJwt = process.env.USER_JWT
      const user2Jwt = process.env.USER_2_JWT

      if (!userJwt || !user2Jwt) {
        console.log(
          'Skipping mixed lock context test - missing USER_JWT or USER_2_JWT',
        )
        return
      }

      const lc = new LockContext()
      const lc2 = new LockContext()
      const lockContext1 = await lc.identify(userJwt)
      const lockContext2 = await lc2.identify(user2Jwt)

      if (lockContext1.failure) {
        throw new Error(`[protect]: ${lockContext1.failure.message}`)
      }

      if (lockContext2.failure) {
        throw new Error(`[protect]: ${lockContext2.failure.message}`)
      }

      // Encrypt first value with USER_JWT lock context
      const encryptedData1 = await protectClient
        .bulkEncrypt([{ id: 'user1', plaintext: 'alice@example.com' }], {
          column: users.email,
          table: users,
        })
        .withLockContext(lockContext1.data)

      if (encryptedData1.failure) {
        throw new Error(`[protect]: ${encryptedData1.failure.message}`)
      }

      // Encrypt second value with USER_2_JWT lock context
      const encryptedData2 = await protectClient
        .bulkEncrypt([{ id: 'user2', plaintext: 'bob@example.com' }], {
          column: users.email,
          table: users,
        })
        .withLockContext(lockContext2.data)

      if (encryptedData2.failure) {
        throw new Error(`[protect]: ${encryptedData2.failure.message}`)
      }

      // Combine both encrypted payloads
      const combinedEncryptedData = [
        ...encryptedData1.data,
        ...encryptedData2.data,
      ]

      // Decrypt with USER_2_JWT lock context
      const decryptedData = await protectClient
        .bulkDecrypt(combinedEncryptedData)
        .withLockContext(lockContext2.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify both payloads are returned
      expect(decryptedData.data).toHaveLength(2)

      // First payload should fail to decrypt since it was encrypted with different lock context
      expect(decryptedData.data[0]).toHaveProperty('id', 'user1')
      expect(decryptedData.data[0]).toHaveProperty('error')
      expect(decryptedData.data[0]).not.toHaveProperty('data')

      // Second payload should be decrypted since it was encrypted with the same lock context
      expect(decryptedData.data[1]).toHaveProperty('id', 'user2')
      expect(decryptedData.data[1]).toHaveProperty('data', 'bob@example.com')
      expect(decryptedData.data[1]).not.toHaveProperty('error')
    }, 30000)
  })

  describe('bulk operations round-trip', () => {
    it('should maintain data integrity through encrypt/decrypt cycle', async () => {
      const originalData = [
        { id: 'user1', plaintext: 'alice@example.com' },
        { id: 'user2', plaintext: 'bob@example.com' },
        { id: 'user3', plaintext: 'dave@example.com' },
      ]

      // Encrypt
      const encryptedData = await protectClient.bulkEncrypt(originalData, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      // Decrypt
      const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify round-trip integrity
      expect(decryptedData.data).toHaveLength(originalData.length)

      for (let i = 0; i < originalData.length; i++) {
        expect(decryptedData.data[i].id).toBe(originalData[i].id)
        expect(decryptedData.data[i].data).toBe(originalData[i].plaintext)
      }
    }, 30000)

    it('should handle large arrays efficiently', async () => {
      const originalData = Array.from({ length: 100 }, (_, i) => ({
        id: `user${i}`,
        plaintext: `user${i}@example.com`,
      }))

      // Encrypt
      const encryptedData = await protectClient.bulkEncrypt(originalData, {
        column: users.email,
        table: users,
      })

      if (encryptedData.failure) {
        throw new Error(`[protect]: ${encryptedData.failure.message}`)
      }

      // Decrypt
      const decryptedData = await protectClient.bulkDecrypt(encryptedData.data)

      if (decryptedData.failure) {
        throw new Error(`[protect]: ${decryptedData.failure.message}`)
      }

      // Verify all data is preserved
      expect(decryptedData.data).toHaveLength(100)

      for (let i = 0; i < 100; i++) {
        expect(decryptedData.data[i].id).toBe(`user${i}`)
        expect(decryptedData.data[i].data).toBe(`user${i}@example.com`)
      }
    }, 30000)
  })
})
