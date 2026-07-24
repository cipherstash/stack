/**
 * Acceptance #1a + #1b + #1c — EQL v2 READ compatibility after the v3 collapse.
 *
 * The client authors EQL v3 only, but MUST keep reading previously stored EQL v2
 * payloads — on the core client (guardrail 1) AND through the DynamoDB adapter
 * (guardrail 2). This suite mints v2 data with a v2-mode `Encryption` client (the
 * retained `config: { eqlVersion: 2 }` escape hatch) and proves it still
 * round-trips:
 *
 *  - #1a: a v2 ciphertext + a v2 model decrypt through the collapsed `Encryption`
 *    client's `decrypt` / `decryptModel`.
 *  - #1b: a stored v2 DynamoDB item — split with the exported
 *    `toEncryptedDynamoItem(payload, attrs, false)` — decrypts through
 *    `encryptedDynamoDB(...).decryptModel(item, v2Table)`, exercising the v2
 *    envelope reconstruction (`toItemWithEqlPayloads`, `v === 2` / `k: 'ct'`).
 *  - #1c: the SAME v2 payloads decrypt through a **v3-configured** client that
 *    has never heard of the v2 table.
 *
 * #1c is the invariant customers actually depend on and the reason this file
 * cannot be a v2-only suite: after the removal their client is v3, their stored
 * data is v2, and #1a/#1b would keep passing even if a v3 client had lost the
 * ability to read v2 — because both mint AND read through the v2-mode client.
 * Whatever eventually deletes the `eqlVersion: 2` minting path must keep #1c
 * alive (against a checked-in ciphertext fixture, or a raw `EncryptConfig`),
 * not delete it along with the escape hatch.
 *
 * Live: requires real ZeroKMS credentials (the integration harness provisions
 * them and throws otherwise). The credential-free half of the v2 read path — the
 * DynamoDB envelope split/reconstruction over static payloads — is covered by
 * `__tests__/dynamodb/helpers.test.ts`, which needs no network at all.
 */
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import type { EncryptionClient } from '@/encryption'
import { encryptedTable as encryptedTableV3, types as typesV3 } from '@/eql/v3'
import { Encryption } from '@/index'
// The deprecated v2 authoring builders remain for reading/migrating legacy data.
import { encryptedColumn, encryptedTable } from '@/schema'

// A minimal EQL v2 table (v2 builders → no `buildColumnKeyMap`, so `Encryption`
// returns the nominal client, not the typed one).
const usersV2 = encryptedTable('v2_read_compat_users', {
  email: encryptedColumn('email').equality(),
})

// A DIFFERENT table, in v3 builders, so the v3 client below carries no knowledge
// of the v2 table whatsoever — reading v2 data must not depend on the v2 schema
// still being registered.
const unrelatedV3 = encryptedTableV3('v2_read_compat_unrelated_v3', {
  note: typesV3.TextEq('note'),
})

const SECRET = 'ada@example.com'

// A v2-mode client: the explicit `eqlVersion: 2` escape hatch forces v2 wire so
// this suite mints genuinely-v2 payloads, independent of schema auto-detection.
let v2Client: EncryptionClient

// The client a customer is left with after the removal: v3 schemas, default
// (v3) wire version. Every read in #1c goes through this one.
//
// Typed through a thunk rather than annotated `EncryptionClient`: a concrete v3
// schema set selects the TYPED overload, and `TypedEncryptionClient` is not
// assignable to the nominal `EncryptionClient`.
const makeV3Client = () => Encryption({ schemas: [unrelatedV3] })
let v3Client: Awaited<ReturnType<typeof makeV3Client>>

beforeAll(async () => {
  v2Client = await Encryption({
    schemas: [usersV2],
    config: { eqlVersion: 2 },
  })
  v3Client = await Encryption({ schemas: [unrelatedV3] })
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

// The real-world shape of the compatibility promise: the customer upgraded, so
// their client is v3-configured and knows nothing about the v2 table — but the
// rows already in their database are v2.
describe('#1c — a v3-configured client reads stored EQL v2 payloads', () => {
  it('decrypts a v2 ciphertext minted before the upgrade', async () => {
    const encrypted = unwrapResult(
      await v2Client.encrypt(SECRET, { table: usersV2, column: usersV2.email }),
    )
    // Guard against a false pass: this must be a genuine v2 payload, or the
    // test proves nothing about v2 compatibility.
    expect(encrypted).toMatchObject({ v: 2 })

    const decrypted = unwrapResult(await v3Client.decrypt(encrypted))
    expect(decrypted).toBe(SECRET)
  }, 30000)

  it('decrypts a v2 model minted before the upgrade', async () => {
    const encryptedModel = unwrapResult(
      await v2Client.encryptModel({ pk: 'a', email: SECRET }, usersV2),
    )
    expect(encryptedModel.email).toMatchObject({ v: 2 })

    const decrypted = unwrapResult(await v3Client.decryptModel(encryptedModel))
    expect(decrypted).toEqual({ pk: 'a', email: SECRET })
  }, 30000)

  it('bulk-decrypts v2 ciphertexts minted before the upgrade', async () => {
    const encrypted = unwrapResult(
      await v2Client.bulkEncrypt(
        [
          { id: '1', plaintext: SECRET },
          { id: '2', plaintext: 'grace@example.com' },
        ],
        { table: usersV2, column: usersV2.email },
      ),
    )

    const decrypted = unwrapResult(await v3Client.bulkDecrypt(encrypted))
    expect(decrypted).toEqual([
      { id: '1', data: SECRET },
      { id: '2', data: 'grace@example.com' },
    ])
  }, 30000)

  it('decrypts a stored v2 DynamoDB item through a v3-configured adapter', async () => {
    const encryptedModel = unwrapResult(
      await v2Client.encryptModel({ pk: 'a', email: SECRET }, usersV2),
    )
    const storedV2Item = toEncryptedDynamoItem(encryptedModel, ['email'], false)

    // The adapter is built on the v3 client; only the TABLE argument still
    // describes the legacy v2 shape, because that is what the item on disk is.
    const dynamo = encryptedDynamoDB({ encryptionClient: v3Client })
    const decrypted = unwrapResult(
      await dynamo.decryptModel(storedV2Item, usersV2),
    )

    expect(decrypted).toMatchObject({ pk: 'a', email: SECRET })
  }, 30000)
})
