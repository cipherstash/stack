import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type CastAs,
  type EncryptConfig,
  decrypt,
  encrypt,
  newClient,
} from '@cipherstash/protect-ffi'

// Import a shared encryptConfig from common.js
import { encryptConfig } from './common.js'

describe('lock context', () => {
  test('can pass in unverified context', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'
    const unverifiedContext = {
      sub: 'sub-single',
    }

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
      unverifiedContext,
    })

    const decrypted = await decrypt(client, {
      ciphertext,
      unverifiedContext,
    })

    expect(decrypted).toBe(originalPlaintext)
  })

  test('encrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    await expect(async () => {
      await encrypt(client, {
        plaintext: originalPlaintext,
        column: 'email',
        table: 'users',
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Request forbidden/)
  }, 10000)

  test('decrypt throws an error when identityClaim is used without a service token', async () => {
    const client = await newClient({ encryptConfig })
    const originalPlaintext = 'abc'

    const ciphertext = await encrypt(client, {
      plaintext: originalPlaintext,
      column: 'email',
      table: 'users',
    })

    await expect(async () => {
      await decrypt(client, {
        ciphertext,
        lockContext: {
          identityClaim: ['sub'],
        },
      })
    }).rejects.toThrowError(/Failed to send request/)
  }, 10000)
})
