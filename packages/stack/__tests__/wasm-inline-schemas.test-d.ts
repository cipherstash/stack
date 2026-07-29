/**
 * The WASM `Encryption` factory must accept the same schema-array shapes the
 * native one does (#815 review).
 *
 * A-4 (`fix(stack)!: accept schema arrays that are not literals`) widened the
 * native factory from a mutable non-empty tuple to `readonly AnyV3Table[]`,
 * because `schemas.map(...)` results and `readonly` arrays are what real
 * callers hold. The WASM twin kept the tuple, so the two entries disagreed
 * about the same call — while their runtimes agree exactly (`!schemas.length`).
 */
import { describe, expectTypeOf, it } from 'vitest'
import { type AnyV3Table, encryptedTable, types } from '@/eql/v3'
import { Encryption, type WasmEncryptionClient } from '@/wasm-inline'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

const config = {
  workspaceCrn: 'crn',
  accessKey: 'key',
  clientId: 'id',
  clientKey: 'client-key',
}

describe('wasm-inline Encryption schema typing', () => {
  it('accepts a literal tuple', async () => {
    expectTypeOf(
      await Encryption({ schemas: [users], config }),
    ).toEqualTypeOf<WasmEncryptionClient>()
  })

  it('accepts a widened array, as the native entry does', async () => {
    const widened: AnyV3Table[] = [users]
    expectTypeOf(
      await Encryption({ schemas: widened, config }),
    ).toEqualTypeOf<WasmEncryptionClient>()
  })

  it('accepts a readonly array, as the native entry does', async () => {
    const frozen: readonly AnyV3Table[] = [users]
    expectTypeOf(
      await Encryption({ schemas: frozen, config }),
    ).toEqualTypeOf<WasmEncryptionClient>()
  })

  it('accepts a generic caller that is itself parameterised over its schemas', async () => {
    async function make<S extends readonly [AnyV3Table, ...AnyV3Table[]]>(
      schemas: S,
    ) {
      return Encryption({ schemas, config })
    }

    expectTypeOf(await make([users])).toEqualTypeOf<WasmEncryptionClient>()
  })

  it('still rejects an empty literal', () => {
    // @ts-expect-error - at least one table is required
    Encryption({ schemas: [], config })
  })
})
