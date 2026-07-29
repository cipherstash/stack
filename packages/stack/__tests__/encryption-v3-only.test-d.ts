import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, type EncryptionClient } from '@/encryption'
import { type AnyV3Table, encryptedTable, types } from '@/eql/v3'
import type { ClientConfig, EncryptionClientConfig } from '@/types'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdAt: types.TimestampOrd('created_at'),
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
