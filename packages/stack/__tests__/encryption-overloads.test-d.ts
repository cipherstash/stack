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
import { type AnyV3Table, types } from '@/eql/v3'
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

  // ...but only when the ARGUMENT'S TYPE has a statically known length of 0.
  // `NonEmptyV3<S>` keys off `S['length'] extends 0`, so once the type widens to
  // `AnyV3Table[]` the length is `number` and emptiness stops being visible —
  // including for a literal at the call site, because a spread erases the tuple.
  // These compile ON PURPOSE: rejecting them is what the A-4 tuple constraint
  // did, and it broke every non-literal caller. The runtime guard is what
  // catches them; `empty-schemas-boundary.test.ts` pins that half, and
  // `skills/stash-encryption` documents the split for users.
  // A generic passthrough is the shape `EncryptionClientFor` and the skill both
  // advertise ("code that is generic over its schemas"), and it is the one form
  // a WIDENING change must not break. It compiled before A-4 and must still.
  //
  // A deferred conditional on the property is what broke it: `S` is assignable
  // to `NonEmptyV3<S>` only if it is assignable to BOTH branches, and one branch
  // is `never`. The emptiness rejection does not need it — overload 2's
  // `AtLeastOneCsTable` rejects `[]` on its own.
  it('accepts schemas from a generic wrapper function', async () => {
    async function makeTypedClient<
      S extends readonly [AnyV3Table, ...AnyV3Table[]],
    >(schemas: S) {
      return await Encryption({ schemas })
    }

    expectTypeOf(await makeTypedClient([users])).toEqualTypeOf<
      TypedEncryptionClient<readonly [typeof users]>
    >()

    // A wrapper generic over a LOOSE `readonly AnyV3Table[]` is still rejected,
    // here and on the pre-A-4 signature alike. That is the honest answer rather
    // than a gap: such an `S` admits `readonly []`, so the wrapper cannot
    // promise what `Encryption` requires. Constrain it to a non-empty tuple, as
    // above, and it compiles.
    async function makeLooseClient<S extends readonly AnyV3Table[]>(
      schemas: S,
    ) {
      // @ts-expect-error - a loose `S` cannot prove it is non-empty
      return await Encryption({ schemas })
    }
    void makeLooseClient
  })

  it('accepts arrays whose type cannot prove non-emptiness', () => {
    const shared: AnyV3Table[] = []
    expectTypeOf(Encryption).toBeCallableWith({ schemas: shared })

    const frozen: ReadonlyArray<AnyV3Table> = []
    expectTypeOf(Encryption).toBeCallableWith({ schemas: frozen })

    expectTypeOf(Encryption).toBeCallableWith({ schemas: [...shared] })
    expectTypeOf(Encryption).toBeCallableWith({
      schemas: shared.filter(() => false),
    })
  })

  // A-4: closing S-6 with a non-empty TUPLE constraint rejected every schema
  // array that is not a literal, which is most real code — a shared module
  // export, anything built from introspection, anything `readonly`. The
  // non-emptiness check moved to the `schemas` property so these compile again
  // while `[]` above still does not. One case per form that was broken.
  it('accepts schema arrays that are not literals', async () => {
    const shared: AnyV3Table[] = [users]
    expectTypeOf(await Encryption({ schemas: shared })).toEqualTypeOf<
      TypedEncryptionClient<AnyV3Table[]>
    >()

    // `ReadonlyArray` is the form `@cipherstash/prisma-next` exposes publicly.
    const frozen: ReadonlyArray<AnyV3Table> = [users]
    expectTypeOf(await Encryption({ schemas: frozen })).toEqualTypeOf<
      TypedEncryptionClient<readonly AnyV3Table[]>
    >()

    const built: AnyV3Table[] = []
    built.push(users)
    expectTypeOf(await Encryption({ schemas: built })).toEqualTypeOf<
      TypedEncryptionClient<AnyV3Table[]>
    >()

    expectTypeOf(await Encryption({ schemas: [...shared] })).toEqualTypeOf<
      TypedEncryptionClient<AnyV3Table[]>
    >()
  })

  // The widening must not cost the literal path its precision — that typing is
  // the entire reason the typed client exists. `const` inference has to survive.
  it('keeps per-column typing on the literal path', async () => {
    const client = await Encryption({ schemas: [users] })

    expectTypeOf(client.encrypt).toBeCallableWith('a@b.com', {
      table: users,
      column: users.email,
    })
    // @ts-expect-error - `email` is a text domain, not a number
    client.encrypt(123, { table: users, column: users.email })
    // @ts-expect-error - `createdAt` is a timestamp domain, not a string
    client.encrypt('2020-01-01', { table: users, column: users.createdAt })
  })

  // S-4: `eqlVersion: 2` selects the NOMINAL overload, because the typed client
  // cannot author v3 columns in v2 mode. The types used to claim the typed
  // client, so `decryptModel(row, table, lockContext)` compiled and then
  // silently dropped `table` and `lockContext`.
  //
  // Over an all-v3 schema set this combination is now REJECTED AT RUNTIME
  // (#772 review, finding 8) — v2 wire into `eql_v3_*` columns is a
  // contradiction, and `EncryptionV3` used to force `eqlVersion: 3` precisely
  // to stop it. This assertion therefore records overload resolution only; the
  // call itself throws. `init-strategy.test.ts` pins the throw.
  it('forcing eqlVersion 2 selects the nominal overload (and is refused at runtime for v3 schemas)', async () => {
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
  it('EncryptionClientFor names the typed client for a v3 tuple', async () => {
    const client: EncryptionClientFor<readonly [typeof users]> =
      await Encryption({ schemas: [users] })
    expectTypeOf(client).toEqualTypeOf<
      TypedEncryptionClient<readonly [typeof users]>
    >()
  })

  // A-6: the form generic code needs — an integration adapter that builds its
  // table per test family cannot name a tuple. This must track `Encryption`'s
  // own constraint: while `EncryptionClientFor` still required a non-empty
  // TUPLE it fell through to the nominal client here, silently handing the
  // wrong type to exactly the callers the widening above exists to serve.
  it('EncryptionClientFor names the typed client for a loose v3 array', () => {
    expectTypeOf<EncryptionClientFor<readonly AnyV3Table[]>>().toEqualTypeOf<
      TypedEncryptionClient<readonly AnyV3Table[]>
    >()
  })

  it('EncryptionClientFor falls back to the nominal client', () => {
    expectTypeOf<
      EncryptionClientFor<readonly [typeof usersV2]>
    >().toEqualTypeOf<EncryptionClient>()

    // `never extends X` is true, so an empty tuple satisfies "every element is
    // a v3 table" — the emptiness arm has to be checked inside the v3 branch.
    expectTypeOf<
      EncryptionClientFor<readonly []>
    >().toEqualTypeOf<EncryptionClient>()
  })

  // S-2: `ReturnType` reads the LAST overload, so this idiom resolves to the
  // nominal client no matter what schemas you pass. Overload order cannot
  // satisfy both forms — putting the nominal signature first mis-resolves v3
  // schemas instead, because a v3 table structurally satisfies `BuildableTable`.
  // `EncryptionClientFor` above is the supported idiom; this pins the trap so it
  // cannot start silently resolving differently.
  it('ReturnType<typeof Encryption> resolves to the NOMINAL client', () => {
    expectTypeOf<
      Awaited<ReturnType<typeof Encryption>>
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
