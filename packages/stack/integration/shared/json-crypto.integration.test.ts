/**
 * Live round-trip for the v3 `types.Json()` column — an encrypted JSONB document
 * stored as an ste_vec `SteVecDocument`. Proves the new json column model
 * encrypts and decrypts a real document through protect-ffi (no DB query here;
 * containment is exercised by the Drizzle json suite).
 */
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable, types } from '@/encryption/v3'

const docs = encryptedTable('v3_json_docs', {
  profile: types.Json('profile'),
})

describe('v3 typed client — JSON (ste_vec) round-trip', () => {
  let client: Awaited<ReturnType<typeof EncryptionV3<[typeof docs]>>>

  beforeAll(async () => {
    client = await EncryptionV3({ schemas: [docs] })
  }, 30000)

  it('round-trips a JSON document through encrypt/decrypt', async () => {
    const value = {
      user: 'ada@example.com',
      roles: ['admin', 'eng'],
      active: true,
      meta: { since: 2020 },
    }

    const encrypted = unwrapResult(
      await client.encrypt(value, { table: docs, column: docs.profile }),
    )
    // An ste_vec document carries an `sv` array, not a scalar `c` ciphertext.
    expect(Array.isArray((encrypted as { sv?: unknown }).sv)).toBe(true)

    const decrypted = unwrapResult(await client.decrypt(encrypted))
    expect(decrypted).toEqual(value)
  }, 30000)

  it('round-trips a JSON document through the model path', async () => {
    const model = { profile: { user: 'grace@example.com', roles: ['eng'] } }
    const encrypted = unwrapResult(await client.encryptModel(model, docs))
    const decrypted = unwrapResult(await client.decryptModel(encrypted, docs))
    expect(decrypted).toEqual(model)
  }, 30000)
})
