import 'dotenv/config'
import { csColumn, csTable } from '@cipherstash/schema'
import { beforeAll, describe, expect, it } from 'vitest'
import { protect } from '../src'

const users = csTable('users', {
  email: csColumn('email'),
})

describe('k-field discriminator (EQL v2.3)', () => {
  let protectClient: Awaited<ReturnType<typeof protect>>

  beforeAll(async () => {
    protectClient = await protect({ schemas: [users] })
  })

  it('encrypts scalar data with k: "ct" discriminator', async () => {
    const testData = 'test@example.com'

    const result = await protectClient.encrypt(testData, {
      column: users.email,
      table: users,
    })

    if (result.failure) {
      throw new Error(`Encryption failed: ${result.failure.message}`)
    }

    expect(result.data).toHaveProperty('k', 'ct')
    expect(result.data).toHaveProperty('c')
    expect(result.data).toHaveProperty('v')
    expect(result.data).toHaveProperty('i')
  }, 30000)

  it('decrypts a payload round-trips back to the original plaintext', async () => {
    const testData = 'roundtrip@example.com'

    const encrypted = await protectClient.encrypt(testData, {
      column: users.email,
      table: users,
    })

    if (encrypted.failure) {
      throw new Error(`Encryption failed: ${encrypted.failure.message}`)
    }

    const result = await protectClient.decrypt(encrypted.data!)

    if (result.failure) {
      throw new Error(`Decryption failed: ${result.failure.message}`)
    }

    expect(result.data).toBe(testData)
  }, 30000)
})
