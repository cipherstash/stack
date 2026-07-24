/**
 * Type-level contract for the `Encryption` overload pair.
 *
 * `Encryption` is overloaded — an all-v3 schema tuple yields the typed client,
 * everything else yields the nominal one — and the two are NOT mutually
 * assignable. Overload selection is therefore load-bearing public API, and none
 * of it is exercised by a runtime test. Each case below was a real defect found
 * in review (#772): a call that type-checked as the typed client but returned
 * the nominal one at runtime, a schema set the types accepted and the runtime
 * threw on, and a `ReturnType` idiom that silently resolves to the wrong client.
 */
import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, type EncryptionClient } from '@/encryption'
import {
  type EncryptionClientFor,
  encryptedTable,
  type TypedEncryptionClient,
} from '@/encryption/v3'
import { types } from '@/eql/v3'
import { encryptedColumn, encryptedTable as encryptedTableV2 } from '@/schema'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdAt: types.TimestampOrd('created_at'),
})

const usersV2 = encryptedTableV2('users_v2', {
  email: encryptedColumn('email').equality(),
})

describe('overload selection', () => {
  it('an all-v3 schema tuple yields the typed client', async () => {
    const client = await Encryption({ schemas: [users] })
    expectTypeOf(client).toEqualTypeOf<
      TypedEncryptionClient<readonly [typeof users]>
    >()
  })

  it('a v2 schema set yields the nominal client', async () => {
    const client = await Encryption({ schemas: [usersV2] })
    expectTypeOf(client).toEqualTypeOf<EncryptionClient>()
  })

  // S-6: `readonly []` satisfies `readonly AnyV3Table[]`, so an empty schema set
  // used to compile and then throw at runtime. Both overloads now require at
  // least one table.
  it('rejects an empty schema set', () => {
    // @ts-expect-error - at least one encryptedTable is required
    Encryption({ schemas: [] })
  })

  // S-4: forcing v2 wire over v3 schemas returns the NOMINAL client at runtime
  // (the typed client cannot author v3 columns in v2 mode). The types used to
  // claim the typed client, so `decryptModel(row, table, lockContext)` compiled
  // and then silently dropped `table` and `lockContext`.
  it('forcing eqlVersion 2 over v3 schemas yields the nominal client', async () => {
    const client = await Encryption({
      schemas: [users],
      config: { eqlVersion: 2 },
    })
    expectTypeOf(client).toEqualTypeOf<EncryptionClient>()
    // The typed-only three-arg decrypt is therefore not available — which is
    // exactly what the runtime does.
    // @ts-expect-error - the nominal client takes the model alone
    client.decryptModel({ email: 'x' }, users)
  })

  it('an explicit eqlVersion 3 keeps the typed client', async () => {
    const client = await Encryption({
      schemas: [users],
      config: { eqlVersion: 3 },
    })
    expectTypeOf(client).toEqualTypeOf<
      TypedEncryptionClient<readonly [typeof users]>
    >()
  })
})

describe('naming the client type', () => {
  // S-2: `ReturnType` reads the LAST overload, so this idiom resolves to the
  // nominal client no matter what schemas you pass. Pinned rather than fixed —
  // overload order cannot satisfy both forms — so the surprise is documented and
  // cannot change silently.
  it('ReturnType<typeof Encryption> resolves to the NOMINAL client', () => {
    expectTypeOf<
      Awaited<ReturnType<typeof Encryption>>
    >().toEqualTypeOf<EncryptionClient>()
  })

  it('EncryptionClientFor names the typed client for a v3 tuple', async () => {
    const client: EncryptionClientFor<readonly [typeof users]> =
      await Encryption({ schemas: [users] })
    expectTypeOf(client).toEqualTypeOf<
      TypedEncryptionClient<readonly [typeof users]>
    >()
  })

  it('EncryptionClientFor falls back to the nominal client', () => {
    expectTypeOf<
      EncryptionClientFor<readonly [typeof usersV2]>
    >().toEqualTypeOf<EncryptionClient>()
  })
})

describe('reading legacy EQL v2 models through a typed client', () => {
  // The compatibility promise: a v3-configured client must read rows written
  // before the upgrade. Their table is not — and cannot be — a member of the
  // client's v3 schema tuple, so the table-less call has to type-check.
  it('accepts a table-less decryptModel', async () => {
    const client = await Encryption({ schemas: [users] })
    expectTypeOf(client.decryptModel).toBeCallableWith({
      pk: 'a',
      email: { k: 'ct', v: 2, c: 'ciphertext', i: { t: 'legacy', c: 'email' } },
    })
    expectTypeOf(client.bulkDecryptModels).toBeCallableWith([
      { pk: 'a', email: { k: 'ct', v: 2, c: 'x', i: { t: 'l', c: 'email' } } },
    ])
  })

  it('still rejects a table this client was not built with', async () => {
    const client = await Encryption({ schemas: [users] })
    const unregistered = encryptedTable('other', { note: types.TextEq('note') })
    // @ts-expect-error - `other` is not a member of the client's schema tuple
    client.decryptModel({ note: 'x' }, unregistered)
  })
})
