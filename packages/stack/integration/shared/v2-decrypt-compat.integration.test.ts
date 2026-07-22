/**
 * Acceptance #1a + #1b — EQL v2 READ compatibility after the v3 collapse (PR 3).
 *
 * PR 3 makes EQL v3 the only generation the client authors/writes, but MUST keep
 * reading previously stored EQL v2 payloads — on the core client (guardrail 1)
 * AND through the DynamoDB adapter (guardrail 2). This suite mints v2 data with a
 * v2-mode `Encryption` client (the retained `config: { eqlVersion: 2 }` escape
 * hatch) and proves it still round-trips:
 *
 *  - #1a: a v2 ciphertext + a v2 model decrypt through the collapsed `Encryption`
 *    client's `decrypt` / `decryptModel`.
 *  - #1b: a stored v2 DynamoDB item — split with the exported
 *    `toEncryptedDynamoItem(payload, attrs, false)` — decrypts through
 *    `encryptedDynamoDB(...).decryptModel(item, v2Table)`, exercising the v2
 *    envelope reconstruction (`toItemWithEqlPayloads`, `v === 2` / `k: 'ct'`).
 *
 * Both fail if the v2 read path is removed. Live: requires real ZeroKMS
 * credentials (the integration harness provisions them and throws otherwise).
 */
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import type { EncryptionClient } from '@/encryption'
import { Encryption } from '@/index'
// The deprecated v2 authoring builders remain for reading/migrating legacy data.
import { encryptedColumn, encryptedTable } from '@/schema'

// A minimal EQL v2 table (v2 builders → no `buildColumnKeyMap`, so `Encryption`
// returns the nominal client, not the typed one).
const usersV2 = encryptedTable('v2_read_compat_users', {
  email: encryptedColumn('email').equality(),
})

const SECRET = 'ada@example.com'

// A v2-mode client: the explicit `eqlVersion: 2` escape hatch forces v2 wire so
// this suite mints genuinely-v2 payloads, independent of schema auto-detection.
let v2Client: EncryptionClient

beforeAll(async () => {
  v2Client = await Encryption({
    schemas: [usersV2],
    config: { eqlVersion: 2 },
  })
})

describe('#1a — core client reads a stored EQL v2 payload', () => {
  it('round-trips a v2 ciphertext through decrypt', async () => {
    const encrypted = unwrapResult(
      await v2Client.encrypt(SECRET, { table: usersV2, column: usersV2.email }),
    )
    // Guard against a false pass: it must be an actual ciphertext.
    expect(encrypted).toHaveProperty('c')

    const decrypted = unwrapResult(await v2Client.decrypt(encrypted))
    expect(decrypted).toBe(SECRET)
  }, 30000)

  it('round-trips a v2 model through decryptModel', async () => {
    const encryptedModel = unwrapResult(
      await v2Client.encryptModel({ pk: 'a', email: SECRET }, usersV2),
    )
    expect(encryptedModel.email).toHaveProperty('c')

    const decrypted = unwrapResult(await v2Client.decryptModel(encryptedModel))
    expect(decrypted).toEqual({ pk: 'a', email: SECRET })
  }, 30000)
})

describe('#1b — DynamoDB adapter reads a stored EQL v2 item', () => {
  it('decrypts a v2-split DynamoDB item via encryptedDynamoDB.decryptModel', async () => {
    // Stage a stored v2 item: encrypt a v2 model, then split it into DynamoDB
    // attributes exactly as the (removed-at-the-type-level, retained-at-runtime)
    // v2 write path would have — `toEncryptedDynamoItem(..., false)`.
    const encryptedModel = unwrapResult(
      await v2Client.encryptModel({ pk: 'a', email: SECRET }, usersV2),
    )
    const storedV2Item = toEncryptedDynamoItem(encryptedModel, ['email'], false)

    // The email column becomes `email__source` (+ `email__hmac` for equality);
    // the plaintext key does not survive the split.
    expect(storedV2Item).toHaveProperty('email__source')
    expect(storedV2Item).not.toHaveProperty('email')
    expect(storedV2Item.pk).toBe('a')

    const dynamo = encryptedDynamoDB({ encryptionClient: v2Client })
    const decrypted = unwrapResult(
      await dynamo.decryptModel(storedV2Item, usersV2),
    )

    expect(decrypted).toMatchObject({ pk: 'a', email: SECRET })
  }, 30000)
})
