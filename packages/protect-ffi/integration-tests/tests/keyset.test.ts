import 'dotenv/config'
import { beforeAll, describe, expect, test } from 'vitest'

import {
  type Identifier,
  decrypt,
  encrypt,
  ensureKeyset,
  isEncrypted,
  newClient,
} from '@cipherstash/protect-ffi'

import { encryptConfig } from './common.js'
type UserColumn = Identifier<typeof encryptConfig>

const stringColumn: UserColumn = {
  table: 'users',
  column: 'email',
}

describe('keyset tests', () => {
  let testKeysetId: string

  beforeAll(async () => {
    const keyset = await ensureKeyset({ name: 'Test' })
    testKeysetId = keyset.id
  })

  test('can round-trip encrypt and decrypt a string using keyset name', async () => {
    const client = await newClient({
      encryptConfig,
      clientOpts: {
        keyset: { Name: 'Test' },
      },
    })

    const identifier = stringColumn
    const plaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext,
      ...identifier,
    })

    expect(isEncrypted(ciphertext)).toBe(true)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe(plaintext)
  })

  test('can round-trip encrypt and decrypt a string using keyset uuid', async () => {
    const client = await newClient({
      encryptConfig,
      clientOpts: {
        keyset: { Uuid: testKeysetId },
      },
    })

    const identifier = stringColumn
    const plaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext,
      ...identifier,
    })

    expect(isEncrypted(ciphertext)).toBe(true)

    const decrypted = await decrypt(client, { ciphertext })
    expect(decrypted).toBe(plaintext)
  })

  test('throws an error when using an invalid keyset', async () => {
    try {
      await newClient({
        encryptConfig,
        clientOpts: {
          keyset: { Name: 'invalid' },
        },
      })
    } catch (error: unknown) {
      expect((error as Error).message.includes('Failed to load keyset')).toBe(
        true,
      )
    }
  }, 10000)
})
