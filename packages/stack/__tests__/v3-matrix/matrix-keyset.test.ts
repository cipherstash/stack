/**
 * Keyset configuration for the v3 typed client (mirrors v2 `keysets.test.ts`).
 * The invalid-UUID case is deterministic — validation happens before any network
 * — so it runs in CI without credentials; the round-trip case is live soft-skip.
 */
import 'dotenv/config'
import { ensureKeyset } from '@cipherstash/protect-ffi'
import { beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable, types } from '@/encryption/v3'
import { unwrapResult } from '../fixtures'
import { describeLive, LIVE_CIPHERSTASH_ENABLED } from '../helpers/live-gate'

const users = encryptedTable('v3_keyset_users', {
  email: types.TextEq('email'),
})

describe('EncryptionV3 keyset config (deterministic)', () => {
  it('rejects an invalid keyset id before touching the network', async () => {
    await expect(
      EncryptionV3({
        schemas: [users],
        config: { keyset: { id: 'invalid-uuid' } },
      }),
    ).rejects.toThrow(
      '[encryption]: Invalid UUID provided for keyset id. Must be a valid UUID.',
    )
  })
})

describeLive('EncryptionV3 keyset config (live)', () => {
  let keysetId: string

  beforeAll(async () => {
    const keyset = await ensureKeyset({ name: 'Test' })
    keysetId = keyset.id
  }, 30000)

  it('round-trips a value using an explicit keyset id', async () => {
    const client = await EncryptionV3({
      schemas: [users],
      config: { keyset: { id: keysetId } },
    })

    const encrypted = unwrapResult(
      await client.encrypt('hello@example.com', {
        table: users,
        column: users.email,
      }),
    )
    expect(encrypted).toHaveProperty('c')

    const decrypted = unwrapResult(await client.decrypt(encrypted))
    expect(decrypted).toBe('hello@example.com')
  }, 30000)
})
