import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, type EncryptionClient } from '@/encryption'
import { type AnyV3Table, encryptedTable, types } from '@/eql/v3'
import type { ClientConfig, EncryptionClientConfig } from '@/types'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdAt: types.TimestampOrd('created_at'),
})

const orders = encryptedTable('orders', {
  total: types.NumericOrdOre('total'),
})

describe('v3-only Encryption contract', () => {
  it('returns the schema-derived client for a literal tuple', async () => {
    const client = await Encryption({ schemas: [users] })
    expectTypeOf(client).toEqualTypeOf<
      EncryptionClient<readonly [typeof users]>
    >()
  })

  it('accepts generic tuples and widened arrays', async () => {
    async function make<S extends readonly [AnyV3Table, ...AnyV3Table[]]>(
      schemas: S,
    ) {
      return Encryption({ schemas })
    }

    expectTypeOf(await make([users])).toEqualTypeOf<
      EncryptionClient<readonly [typeof users]>
    >()

    const widened: AnyV3Table[] = [users]
    expectTypeOf(await Encryption({ schemas: widened })).toEqualTypeOf<
      EncryptionClient<AnyV3Table[]>
    >()
  })

  it('rejects empty literals and removed version configuration', () => {
    // @ts-expect-error - at least one table is required
    Encryption({ schemas: [] })
    const config: ClientConfig = {
      // @ts-expect-error - Stack always authors EQL v3
      eqlVersion: 2,
    }
    void config
  })

  it('uses EncryptionClient<S> as the named client type', () => {
    expectTypeOf<Awaited<ReturnType<typeof Encryption>>>().toEqualTypeOf<
      EncryptionClient<readonly AnyV3Table[]>
    >()
  })
})

/**
 * `getSchemas()` is the first member to put `S` in an OUTPUT position. Every
 * earlier use was `S[number]` or a constraint, so the readonly-vs-mutable
 * distinction on the schema tuple was unobservable and
 * `EncryptionClient<[T]>` and `EncryptionClient<readonly [T]>` were literally
 * the same type. Both spellings arise from ordinary calls — the factory's
 * `const S` infers the READONLY tuple from an array literal, while a caller
 * that is itself generic over its schemas (`make` above) infers the MUTABLE
 * one — and they must keep naming one client type, or the two call styles
 * silently produce incompatible clients.
 *
 * `getSchemas(): Readonly<S>` is what holds that, and it is also the only
 * honest return type: the accessor hands back `Object.freeze(schemas)`, whose
 * type is exactly `Readonly<S>`.
 *
 * The first test below looks tautological and is not. `Readonly<S>` is a
 * homomorphic mapped type, which leaves `S`'s variance UNMEASURABLE, so the
 * identity relation compares the two clients structurally and they agree. The
 * equivalent-looking `readonly [...S]` makes the variance measurable, the
 * relation short-circuits to comparing type arguments, and `[T]` is not
 * identical to `readonly [T]` — so the two client types come apart even though
 * every member still resolves the same. That failure mode is invisible from
 * the source; this test is where it shows up.
 */
declare const mutableTupleClient: EncryptionClient<
  [typeof users, typeof orders]
>

describe('EncryptionClient.getSchemas', () => {
  it('does not distinguish a mutable schema tuple from a readonly one', () => {
    expectTypeOf<
      EncryptionClient<[typeof users, typeof orders]>
    >().toEqualTypeOf<
      EncryptionClient<readonly [typeof users, typeof orders]>
    >()
  })

  it('returns a readonly tuple even when S itself is mutable', () => {
    expectTypeOf(mutableTupleClient.getSchemas()).toEqualTypeOf<
      readonly [typeof users, typeof orders]
    >()
  })

  it('keeps each table precise rather than collapsing to AnyV3Table', async () => {
    const client = await Encryption({ schemas: [users, orders] })

    expectTypeOf(client.getSchemas()).toEqualTypeOf<
      readonly [typeof users, typeof orders]
    >()
    // Positional and per-table. `stash eql validate` reads `getEqlType()` off
    // each column, so an element type widened to `AnyV3Table` — or a tuple
    // flattened to `readonly AnyV3Table[]` — would take the domain away.
    expectTypeOf(client.getSchemas()[0]).toEqualTypeOf<typeof users>()
    expectTypeOf(client.getSchemas()[1]).toEqualTypeOf<typeof orders>()
    expectTypeOf(
      client.getSchemas()[0].columnBuilders.email.getEqlType(),
    ).toEqualTypeOf<'public.eql_v3_text_eq'>()
  })

  it('rejects mutation of the tuple it hands back', async () => {
    const client = await Encryption({ schemas: [users] })

    // @ts-expect-error - the accessor returns the frozen tuple; mutating it
    // would leave getSchemas() describing a schema set the client's
    // reconstructor map was never built for.
    client.getSchemas().push(orders)
  })
})

/**
 * The exported config type must not launder an empty schema set — the same guard
 * `wasm-inline-schemas.test-d.ts` holds for `WasmEncryptionConfig`.
 *
 * `@ts-expect-error` on the inline `Encryption({ schemas: [] })` above is not
 * enough on its own: it only covers a FRESH literal. A config built once and
 * passed around — the shape this type exists to serve — went through a default
 * type argument of `readonly AnyV3Table[]`, where `S['length']` widens to
 * `number`, `number extends 0` is false, and the conditional collapses back to
 * the widened array. It typechecked clean and threw at `Encryption()`.
 */
describe('EncryptionClientConfig', () => {
  it('rejects an empty schema set on the exported config type', () => {
    // @ts-expect-error - at least one table is required
    const cfg: EncryptionClientConfig = { schemas: [] }
    void cfg
  })

  it('accepts a populated config and passes it to the factory', async () => {
    const cfg: EncryptionClientConfig = { schemas: [users] }
    expectTypeOf(await Encryption(cfg)).toEqualTypeOf<
      EncryptionClient<readonly [AnyV3Table, ...AnyV3Table[]]>
    >()
  })

  it('still parameterizes over an explicit schema tuple', () => {
    expectTypeOf<
      EncryptionClientConfig<readonly [typeof users]>['schemas']
    >().toEqualTypeOf<readonly [typeof users]>()
  })

  it('still accepts a widened array passed inline to the factory', async () => {
    const widened: AnyV3Table[] = [users]
    expectTypeOf(await Encryption({ schemas: widened })).toEqualTypeOf<
      EncryptionClient<AnyV3Table[]>
    >()
  })
})
