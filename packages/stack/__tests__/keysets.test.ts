import 'dotenv/config'
import { ensureKeyset } from '@cipherstash/protect-ffi'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

const users = encryptedTable('users', {
  email: types.Text('email'),
})

let testKeysetId: string

beforeAll(async () => {
  const keyset = await ensureKeyset({ name: 'Test' })
  testKeysetId = keyset.id
})

describe('encryption and decryption with keyset id', () => {
  it('should encrypt and decrypt a payload', async () => {
    const protectClient = await Encryption({
      schemas: [users],
      config: {
        keyset: {
          id: testKeysetId,
        },
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
    const protectClient = await Encryption({
      schemas: [users],
      config: {
        keyset: {
          name: 'Test',
        },
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
      Encryption({
        schemas: [users],
        config: {
          keyset: {
            id: 'invalid-uuid',
          },
        },
      }),
    ).rejects.toThrow(
      '[encryption]: Invalid UUID provided for keyset id. Must be a valid UUID.',
    )
  })
})
