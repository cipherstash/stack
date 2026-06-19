import 'dotenv/config'
import { ensureKeyset } from '@cipherstash/protect-ffi'
import { csColumn, csTable } from '@cipherstash/schema'
import { beforeAll, describe, expect, it } from 'vitest'
import { protect } from '../src'

const users = csTable('users', {
  email: csColumn('email'),
})

let testKeysetId: string

beforeAll(async () => {
  const keyset = await ensureKeyset({ name: 'Test' })
  testKeysetId = keyset.id
})

describe('encryption and decryption with keyset id', () => {
  it('should encrypt and decrypt a payload', async () => {
    const protectClient = await protect({
      schemas: [users],
      keyset: {
        id: testKeysetId,
      },
    })

    const email = 'hello@example.com'

    const ciphertext = await protectClient.encrypt(email, {
      column: users.email,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('c')

    const a = ciphertext.data

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: email,
    })
  }, 30000)
})

describe('encryption and decryption with keyset name', () => {
  it('should encrypt and decrypt a payload', async () => {
    const protectClient = await protect({
      schemas: [users],
      keyset: {
        name: 'Test',
      },
    })

    const email = 'hello@example.com'

    const ciphertext = await protectClient.encrypt(email, {
      column: users.email,
      table: users,
    })

    if (ciphertext.failure) {
      throw new Error(`[protect]: ${ciphertext.failure.message}`)
    }

    // Verify encrypted field
    expect(ciphertext.data).toHaveProperty('c')

    const a = ciphertext.data

    const plaintext = await protectClient.decrypt(ciphertext.data)

    expect(plaintext).toEqual({
      data: email,
    })
  }, 30000)
})

describe('encryption and decryption with invalid keyset id', () => {
  it('should throw an error', async () => {
    await expect(
      protect({
        schemas: [users],
        keyset: {
          id: 'invalid-uuid',
        },
      }),
    ).rejects.toThrow(
      '[protect]: Invalid UUID provided for keyset id. Must be a valid UUID.',
    )
  })
})
