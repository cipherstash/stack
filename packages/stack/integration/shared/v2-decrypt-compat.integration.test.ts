/**
 * Native v2 read compatibility after removal of the public v2 authoring path.
 *
 * Fixtures are minted directly with protect-ffi in EQL v2 mode. This is
 * deliberately integration-only: production callers cannot select v2 writes,
 * while the native v3 client must continue to decrypt data written before the
 * upgrade.
 *
 * Two blocks, and the SECOND is the one that carries the promise:
 *
 *  - `native v3 client reads stored EQL v2 payloads` — a v3 client reads v2 data
 *    for a table it still registers. The everyday case, but a weak detector: the
 *    reading client is configured for exactly the table the fixtures name, so it
 *    would keep passing even if decrypt started resolving payloads through the
 *    encrypt config.
 *  - `a client that never registered the v2 table still reads its payloads` —
 *    the same fixtures, read through a client configured ONLY for an unrelated
 *    table. This is what a real customer is left with: they migrated, their
 *    schema is whatever they author today, and their database still holds v2
 *    rows for columns their current schema may no longer mention at all.
 *
 * The unrelated table is the entire point of the second block, and it is not
 * obvious on sight: it forces the reads to prove that decrypt is
 * PAYLOAD-SHAPE-DRIVEN and never consults the encrypt config. Nothing looks up
 * `i.t` / `i.c` — `isEncryptedPayload` selects fields structurally
 * (`src/encryption/helpers/index.ts`, `helpers/model-traversal.ts`) and
 * protect-ffi's `decrypt` accepts either wire generation regardless of the
 * client's own `eqlVersion`. Delete the unrelated table, or point these reads
 * back at `users`, and the block silently stops testing anything.
 *
 * Whatever next removes code here must keep that second block alive. It is the
 * successor to the `#1c` case that guarded this invariant while the
 * `config: { eqlVersion: 2 }` escape hatch still existed; the hatch is gone
 * (`Encryption()` now rejects the field outright), the invariant is not.
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

/**
 * A DIFFERENT table, sharing no name or column with `users`. `unrelatedClient`
 * below is built on this one alone, so its encrypt config has never heard of
 * `v2_read_compat_users` — which is what makes the reads in the second describe
 * block load-bearing rather than incidental.
 */
const unrelated = encryptedTable('v2_read_compat_unrelated_v3', {
  note: types.TextEq('note'),
})

const SECRET = 'ada@example.com'
let fixtureClient: Awaited<ReturnType<typeof newFfiClient>>
let client: Awaited<ReturnType<typeof makeClient>>
let unrelatedClient: Awaited<ReturnType<typeof makeUnrelatedClient>>

const makeClient = () => Encryption({ schemas: [users] })
// Typed through a thunk for the same reason as `makeClient`: a concrete schema
// tuple selects the typed overload, whose result is not the nominal client type.
const makeUnrelatedClient = () => Encryption({ schemas: [unrelated] })

beforeAll(async () => {
  fixtureClient = await newFfiClient({
    encryptConfig: buildEncryptConfig(users),
    eqlVersion: 2,
  })
  client = await makeClient()
  unrelatedClient = await makeUnrelatedClient()
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
    // protect-ffi's `EncryptPayload` is `{ plaintext, column, table, lockContext? }`
    // — it carries no `id`, and correlates results positionally. The `id`s below
    // belong to `bulkDecrypt`, which is this package's own API and does take them.
    const encrypted = (await ffiEncryptBulk(fixtureClient, {
      plaintexts: [
        { plaintext: SECRET, table: users.tableName, column: 'email' },
        {
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

/**
 * The invariant customers actually depend on: decrypt is driven by the payload,
 * never by the encrypt config. Every read below goes through `unrelatedClient`,
 * which is configured for `v2_read_compat_unrelated_v3` and nothing else, while
 * the fixtures carry `i.t = 'v2_read_compat_users'`. A customer whose schema
 * dropped or renamed a column — or who never re-declared it after migrating to
 * v3 — must still be able to read the v2 rows already on disk.
 *
 * Keep this block reading through `unrelatedClient`. Swapping it for `client`
 * would leave every assertion green while testing nothing the block above does
 * not already cover.
 */
describe('a client that never registered the v2 table still reads its payloads', () => {
  // Precondition for everything below. If `unrelatedClient` ever ends up
  // registering `users` — a stray schema added here, a factory that merges
  // configs — the cases become indistinguishable from the first block and pass
  // vacuously. Assert the absence directly rather than trusting the setup.
  it('is configured for the unrelated table alone, or the cases below prove nothing', () => {
    const tables = unrelatedClient.getEncryptConfig()?.tables
    expect(Object.keys(tables ?? {})).toEqual([unrelated.tableName])
    expect(tables).not.toHaveProperty(users.tableName)
  })

  it('decrypts a scalar ciphertext for an unregistered table', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    // Guard against a false pass: this must be genuinely v2 wire, and it must
    // name the table the reading client does not have.
    expect(encrypted).toMatchObject({
      v: 2,
      i: { t: users.tableName, c: 'email' },
    })

    expect(unwrapResult(await unrelatedClient.decrypt(encrypted))).toBe(SECRET)
  }, 30000)

  it('decrypts a model whose encrypted field belongs to an unregistered table', async () => {
    const encrypted = await v2Ciphertext(SECRET)

    // No table argument: field selection is structural (`isEncryptedPayload`),
    // so there is nothing for the client to look the column up in.
    expect(
      unwrapResult(
        await unrelatedClient.decryptModel({ pk: 'a', email: encrypted }),
      ),
    ).toEqual({ pk: 'a', email: SECRET })
  }, 30000)

  it('bulk-decrypts ciphertexts for an unregistered table', async () => {
    // Minted one at a time rather than through `ffiEncryptBulk`: the bulk path
    // is on the READ side here, and the fixtures only need to be v2. (The
    // block above already covers the bulk mint.)
    const [first, second] = await Promise.all([
      v2Ciphertext(SECRET),
      v2Ciphertext('grace@example.com'),
    ])

    const decrypted = unwrapResult(
      await unrelatedClient.bulkDecrypt([
        { id: '1', data: first },
        { id: '2', data: second },
      ]),
    )
    expect(decrypted).toEqual([
      { id: '1', data: SECRET },
      { id: '2', data: 'grace@example.com' },
    ])
  }, 30000)

  /**
   * The adapter reaches the same conclusion by a different route, so it needs
   * its own case. `assertClientTableVersionMatch` normally REFUSES a table the
   * client has not registered — that guard catches a v3 write aimed at the
   * wrong client — but it early-returns for `storedEqlVersion: 2`
   * (`src/dynamodb/index.ts`), precisely because a v2 payload says nothing
   * about which v3 tables the client holds. The table argument survives only to
   * drive envelope reconstruction. If that early return is ever tightened into
   * a registration check, this case is what fails.
   */
  it('decrypts a stored v2 DynamoDB item through an adapter on the unrelated client', async () => {
    const encrypted = await v2Ciphertext(SECRET)
    const stored = toEncryptedDynamoItem({ pk: 'a', email: encrypted }, [
      'email',
    ])
    const dynamo = encryptedDynamoDB({ encryptionClient: unrelatedClient })

    const decrypted = unwrapResult(
      await dynamo.decryptModel(stored, users, { storedEqlVersion: 2 }),
    )
    expect(decrypted).toMatchObject({ pk: 'a', email: SECRET })
  }, 30000)
})
