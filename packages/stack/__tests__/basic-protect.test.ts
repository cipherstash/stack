import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  address: types.TextMatch('address'),
  json: types.Json('json'),
})

let protectClient: EncryptionClient

beforeAll(async () => {
  protectClient = await Encryption({
    schemas: [users],
  })
})

describe('encryption and decryption', () => {
  it('should encrypt and decrypt a payload', async () => {
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
