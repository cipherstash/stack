/**
 * Native v2 read compatibility after removal of the public v2 authoring path.
 *
 * Fixtures are minted directly with protect-ffi in EQL v2 mode. This is
 * deliberately integration-only: production callers cannot select v2 writes,
 * while the native v3 client must continue to decrypt data written before the
 * upgrade.
 */
import {
  encrypt as ffiEncrypt,
  encryptBulk as ffiEncryptBulk,
  newClient as newFfiClient,
} from '@cipherstash/protect-ffi'
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import { buildEncryptConfig, encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'
import type { Encrypted } from '@/types'

const users = encryptedTable('v2_read_compat_users', {
  email: types.TextEq('email'),
  altEmail: types.TextEq('alt_email'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof makeClient>>

const makeClient = () => Encryption({ schemas: [users] })

beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await makeClient()
})

async function v2Ciphertext(value: string): Promise<Encrypted> {
  return (await ffiEncrypt(fixtureClient, {
    plaintext: value,
    table: users.tableName,
    column: users.email.getName(),
  })) as Encrypted
}

describe('native v3 client reads stored EQL v2 payloads', () => {
  it('decrypts a scalar ciphertext', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    expect(encrypted).toMatchObject({ v: 2 })

    expect(unwrapResult(await client.decrypt(encrypted))).toBe(SECRET)
  }, 30000)

  it('decrypts a model without registering a legacy schema', async () => {
    const encrypted = await v2Ciphertext(SECRET)

    expect(
      unwrapResult(await client.decryptModel({ pk: 'a', email: encrypted })),
    ).toEqual({ pk: 'a', email: SECRET })
  }, 30000)

  /**
   * The state a real migration actually leaves behind: rows written before the
   * upgrade sit alongside rows written after, and a single model carries both.
   * Every other case here is all-v2, which is only ever true immediately before
   * the first v3 write.
   */
  it('decrypts a model mixing v2 and v3 fields', async () => {
    const legacy = await v2Ciphertext(SECRET)
    const current = unwrapResult(
      await client.encrypt('grace@example.com', {
        table: users,
        column: users.altEmail,
      }),
    )
    expect(legacy).toMatchObject({ v: 2 })
    expect(current).toMatchObject({ v: 3 })

    expect(
      unwrapResult(
        await client.decryptModel(
          { pk: 'a', email: legacy, altEmail: current },
          users,
        ),
      ),
    ).toEqual({ pk: 'a', email: SECRET, altEmail: 'grace@example.com' })
  }, 30000)

  it('bulk-decrypts v2 ciphertexts', async () => {
    const encrypted = (await ffiEncryptBulk(fixtureClient, {
      plaintexts: [
        { id: '1', plaintext: SECRET, table: users.tableName, column: 'email' },
        {
          id: '2',
          plaintext: 'grace@example.com',
          table: users.tableName,
          column: 'email',
        },
      ],
    })) as Encrypted[]

    const decrypted = unwrapResult(
      await client.bulkDecrypt([
        { id: '1', data: encrypted[0] },
        { id: '2', data: encrypted[1] },
      ]),
    )
    expect(decrypted).toEqual([
      { id: '1', data: SECRET },
      { id: '2', data: 'grace@example.com' },
    ])
  }, 30000)

  it('decrypts a DynamoDB item reconstructed as stored EQL v2', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    const stored = toEncryptedDynamoItem({ pk: 'a', email: encrypted }, [
      'email',
    ])
    const dynamo = encryptedDynamoDB({ encryptionClient: client })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(stored, users, { storedEqlVersion: 2 }),
    )
    expect(decrypted).toMatchObject({ pk: 'a', email: SECRET })
  }, 30000)
})
