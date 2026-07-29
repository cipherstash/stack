/**
 * WASM v2 read compatibility (#815 review).
 *
 * The native entry's equivalent lives in `integration/shared/`. This is the
 * edge/serverless half of the same obligation: a customer on Deno, Bun,
 * Cloudflare Workers or Supabase Edge Functions with rows written before the v3
 * migration must still be able to read them.
 *
 * The pairing used to be refused outright by `encryptedDynamoDB` on the belief
 * that the WASM entry could not serve a legacy read. It can: both bindings are
 * builds of the same protect-ffi crate, whose `decrypt` accepts either wire
 * generation regardless of the client's `eqlVersion`. This suite is the
 * executable proof of that claim — the refusal was lifted on its strength.
 *
 * Fixtures are minted directly with protect-ffi in EQL v2 mode, exactly as the
 * shared suite does: production callers cannot select v2 writes on either entry.
 */
import {
  encrypt as ffiEncrypt,
  newClient as newFfiClient,
} from '@cipherstash/protect-ffi'
import { unwrapResult } from '@cipherstash/test-kit'
import { beforeAll, describe, expect, it } from 'vitest'
import { encryptedDynamoDB } from '@/dynamodb'
import { toEncryptedDynamoItem } from '@/dynamodb/helpers'
import { buildEncryptConfig, encryptedTable, types } from '@/eql/v3'
import type { Encrypted } from '@/types'
import { Encryption as WasmEncryption } from '@/wasm-inline'

const users = encryptedTable('wasm_v2_read_compat_users', {
  email: types.TextEq('email'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof WasmEncryption>>

/**
 * The WASM factory hard-requires explicit credentials — no dev-profile
 * fallback (#663) — so read them straight from the environment. The
 * integration harness has already asserted they exist.
 */
beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await WasmEncryption({
    schemas: [users],
    config: {
      workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
      accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
      clientId: process.env.CS_CLIENT_ID as string,
      clientKey: process.env.CS_CLIENT_KEY as string,
    },
  })
})

async function v2Ciphertext(value: string): Promise<Encrypted> {
  return (await ffiEncrypt(fixtureClient, {
    plaintext: value,
    table: users.tableName,
    column: users.email.getName(),
  })) as Encrypted
}

describe('wasm-inline v3 client reads stored EQL v2 payloads', () => {
  it('decrypts a scalar ciphertext', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    expect(encrypted).toMatchObject({ v: 2 })

    expect(unwrapResult(await client.decrypt(encrypted))).toBe(SECRET)
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
