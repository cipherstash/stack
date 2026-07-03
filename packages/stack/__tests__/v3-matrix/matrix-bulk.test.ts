/**
 * Bulk-at-scale proof for the v3 typed client (mirrors v2 `bulk-protect.test.ts`).
 * The only pre-existing v3 bulk test ran against a hand-written stub; this one
 * round-trips 100 models through the v3 typed client's `bulkEncryptModels` /
 * `bulkDecryptModels` against real FFI, exercising v3 model reconstruction at
 * scale. Live soft-skip.
 */
import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import {
  EncryptionV3,
  encryptedInt4OrdColumn,
  encryptedTable,
  encryptedTextEqColumn,
} from '@/encryption/v3'
import { unwrapResult } from '../fixtures'

const LIVE_CIPHERSTASH_ENABLED = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)
const describeLive = LIVE_CIPHERSTASH_ENABLED ? describe : describe.skip

const people = encryptedTable('v3_bulk_people', {
  nickname: encryptedTextEqColumn('nickname'),
  age: encryptedInt4OrdColumn('age'),
})

describeLive('v3 typed client bulk-at-scale (live)', () => {
  let client: Awaited<ReturnType<typeof EncryptionV3<[typeof people]>>>

  beforeAll(async () => {
    client = await EncryptionV3({ schemas: [people] })
  }, 30000)

  it('round-trips 100 models through bulkEncryptModels/bulkDecryptModels', async () => {
    const rows = Array.from({ length: 100 }, (_, i) => ({
      nickname: `user-${i}`,
      age: i,
    }))

    const encrypted = unwrapResult(await client.bulkEncryptModels(rows, people))
    expect(encrypted).toHaveLength(100)
    // Guard: every model field is a real ciphertext, not a plaintext passthrough.
    expect(encrypted[0].nickname).toHaveProperty('c')
    expect(encrypted[0].age).toHaveProperty('c')

    const decrypted = unwrapResult(
      await client.bulkDecryptModels(encrypted, people),
    )
    expect(decrypted).toHaveLength(100)
    for (let i = 0; i < 100; i++) {
      expect(decrypted[i].nickname).toBe(`user-${i}`)
      expect(decrypted[i].age).toBe(i)
    }
  }, 60000)
})
