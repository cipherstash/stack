import { describe, expectTypeOf, it } from 'vitest'
import type { EncryptionClient } from '@/encryption'
import type { EncryptionV3 } from '@/encryption/v3'
import { createEncryptionOperatorsV3 } from '@/eql/v3/drizzle'

/**
 * Static regression guard for M1: `createEncryptionOperatorsV3` must accept the
 * `TypedEncryptionClient` that `EncryptionV3` resolves to — the documented
 * `createEncryptionOperatorsV3(await EncryptionV3({ schemas }))` usage — as well
 * as the nominal `EncryptionClient` and a hand-rolled `{ encrypt }` double,
 * none requiring a cast. Typing the parameter to `EncryptionClient` (the
 * original bug) makes the first call below a compile error, which this suite
 * would then catch. Lives in a `*.test-d.ts` so it is inside the existing
 * typecheck scope without dragging the loose-typed runtime suites in.
 */
describe('createEncryptionOperatorsV3 - client parameter (M1)', () => {
  type V3Client = Awaited<ReturnType<typeof EncryptionV3>>

  it('accepts the client EncryptionV3 returns with no cast', () => {
    expectTypeOf(createEncryptionOperatorsV3).toBeCallableWith({} as V3Client)
  })

  it('still accepts the nominal EncryptionClient', () => {
    expectTypeOf(createEncryptionOperatorsV3).toBeCallableWith(
      {} as EncryptionClient,
    )
  })

  it('accepts a minimal structural { encrypt } double', () => {
    const double = {
      encrypt: (_plaintext: never, _opts: never) => ({}) as unknown,
    }
    expectTypeOf(createEncryptionOperatorsV3).toBeCallableWith(double)
  })
})
