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
 *
 * The shared suite's second block — v2 payloads read through a client that never
 * registered their table — is mirrored here by ONE case, deliberately narrow.
 * The invariant it protects (decrypt is payload-shape-driven and never consults
 * the encrypt config) is enforced in two places, and only one of them is shared
 * between the entries: the field-selection helpers are the same TypeScript on
 * both, but `decrypt` itself is a separate compiled artifact per binding. So the
 * native suite proving the native binding ignores its `encryptConfig` says
 * nothing about the WASM one, and that gap is what the case below closes.
 *
 * The rest of the shared block is not duplicated on purpose. Its DynamoDB case
 * exercises the `storedEqlVersion: 2` early return in
 * `assertClientTableVersionMatch`, which is entry-agnostic TypeScript already
 * covered there; re-running it against the WASM client would re-test the same
 * branch rather than the WASM binding. Nor is there a `getEncryptConfig()`
 * precondition here — this entry's client does not expose one, and the client is
 * constructed from `schemas: [unrelated]` a few lines below with nothing merging
 * into it.
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

/**
 * A DIFFERENT table, sharing no name or column with `users`, so `unrelatedClient`
 * below has never heard of `wasm_v2_read_compat_users`. See the header for why
 * that unregistered read is the case worth carrying onto this entry.
 */
const unrelated = encryptedTable('wasm_v2_read_compat_unrelated_v3', {
  note: types.TextEq('note'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof WasmEncryption>>
let unrelatedClient: Awaited<ReturnType<typeof WasmEncryption>>

/**
 * The WASM factory hard-requires explicit credentials — no dev-profile
 * fallback (#663) — so read them straight from the environment. The
 * integration harness has already asserted they exist.
 */
const wasmCredentials = () => ({
  workspaceCrn: process.env.CS_WORKSPACE_CRN as string,
  accessKey: process.env.CS_CLIENT_ACCESS_KEY as string,
  clientId: process.env.CS_CLIENT_ID as string,
  clientKey: process.env.CS_CLIENT_KEY as string,
})

beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await WasmEncryption({
    schemas: [users],
    config: wasmCredentials(),
  })
  unrelatedClient = await WasmEncryption({
    schemas: [unrelated],
    config: wasmCredentials(),
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

  /**
   * Keep this reading through `unrelatedClient`. Pointed back at `client` it
   * becomes a duplicate of the first case, green forever, and the WASM binding's
   * half of the payload-shape-driven invariant goes uncovered.
   */
  it('decrypts a ciphertext for a table this client never registered', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    // Guard against a false pass: genuinely v2 wire, and naming the table the
    // reading client was not built with.
    expect(encrypted).toMatchObject({
      v: 2,
      i: { t: users.tableName, c: 'email' },
    })

    expect(unwrapResult(await unrelatedClient.decrypt(encrypted))).toBe(SECRET)
  }, 30000)
})
