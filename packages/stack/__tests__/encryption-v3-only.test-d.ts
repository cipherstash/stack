import { describe, expectTypeOf, it } from 'vitest'
import { Encryption, type EncryptionClient } from '@/encryption'
import { type AnyV3Table, encryptedTable, types } from '@/eql/v3'
import type { ClientConfig } from '@/types'

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
