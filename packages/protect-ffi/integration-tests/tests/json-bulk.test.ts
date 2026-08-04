import 'dotenv/config'
import { describe, expect, test } from 'vitest'

import {
  type Identifier,
  decryptBulk,
  encryptBulk,
  newClient,
} from '@cipherstash/protect-ffi'

// Import shared encryptConfig from common.js
import { jsonOpaque, jsonSteVec } from './common.js'

type UserColumn = Identifier<typeof jsonOpaque>

const userProfile: UserColumn = {
  table: 'users',
  column: 'profile',
}

// There are 2 ways we might want to handle JSON data:
// 1. As an opaque blob - we don't care about the structure of the data, we just
//    want to store and retrieve it as-is.
// 2. As a structured object - we want to be able to query and index the data,
//    so we need to know the structure of the data.
//
// In this test suite, we'll test both options.
describe.each([
  { encryptConfig: jsonOpaque, description: 'opaque' },
  { encryptConfig: jsonSteVec, description: 'ste_vec' },
])(
  'Can round-trip encrypt & decrypt JSON',
  async ({ encryptConfig, description }) => {
    describe(`using ${description} config`, () => {
      test('object', async () => {
        const client = await newClient({ encryptConfig })
        const plaintexts = [
          { foo: 'bar', baz: 123 },
          { foo: 'baz', baz: 456 },
        ]

        const ciphertexts = await encryptBulk(client, {
          plaintexts: plaintexts.map((plaintext) => ({
            plaintext,
            ...userProfile,
          })),
        })
        const decrypted = await decryptBulk(client, {
          ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
        })
        expect(decrypted).toEqual(plaintexts)
      })

      test('array object mixed', async () => {
        const client = await newClient({ encryptConfig })
        const plaintexts = [[1, 2, 3], { foo: 'baz', baz: 456 }]

        const ciphertexts = await encryptBulk(client, {
          plaintexts: plaintexts.map((plaintext) => ({
            plaintext,
            ...userProfile,
          })),
        })

        const decrypted = await decryptBulk(client, {
          ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
        })

        expect(decrypted).toEqual(plaintexts)
      })

      test('nested variants', async () => {
        const client = await newClient({ encryptConfig })
        const plaintexts = [
          { foo: 'bar', baz: [1, 2, 3] },
          { foo: 'bar', baz: [{ qux: 'quux' }] },
          { foo: 'bar', baz: { qux: 'quux' } },
        ]

        const ciphertexts = await encryptBulk(client, {
          plaintexts: plaintexts.map((plaintext) => ({
            plaintext,
            ...userProfile,
          })),
        })

        const decrypted = await decryptBulk(client, {
          ciphertexts: ciphertexts.map((ciphertext) => ({ ciphertext })),
        })

        expect(decrypted).toEqual(plaintexts)
      })
    })
  },
)
