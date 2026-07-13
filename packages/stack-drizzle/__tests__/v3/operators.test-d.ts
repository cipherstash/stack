import type { Result } from '@byteslice/result'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { EncryptionError } from '@cipherstash/stack/errors'
import type { LockContext } from '@cipherstash/stack/identity'
import type { Encrypted } from '@cipherstash/stack/types'
import type { EncryptionV3 } from '@cipherstash/stack/v3'
import { describe, expectTypeOf, it } from 'vitest'
import { createEncryptionOperatorsV3 } from '../../src/v3/index.js'

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
    // The double now models what the real client returns: an operation whose
    // `then` resolves a `Result<Encrypted, …>`, not `unknown`. That is the point
    // of the un-erasure — a `{ encrypt }` returning `unknown` no longer
    // typechecks, because the factory reads `result.data` as an `Encrypted`
    // envelope rather than casting it.
    type Op = {
      withLockContext(lc: LockContext): Op
      audit(cfg: AuditConfig): Op
      then: PromiseLike<Result<Encrypted, EncryptionError>>['then']
    }
    const double = {
      encrypt: (_plaintext: never, _opts: never) => ({}) as Op,
    }
    expectTypeOf(createEncryptionOperatorsV3).toBeCallableWith(double)
  })

  it('rejects a { encrypt } double that returns `unknown` (the erasure regression)', () => {
    // The complement of the test above, and the one with teeth: `toBeCallableWith`
    // a correctly-typed double keeps passing even if the client contract
    // regressed to `unknown` (a correct value is assignable to `unknown`), so it
    // cannot catch re-erasure. This can. `encrypt` returning `unknown` must NOT
    // satisfy the factory, whose contract is `ChainableOperation<Encrypted>`; if
    // the erasure ever comes back, the `@ts-expect-error` goes unused and fails.
    const erased = {
      encrypt: (_plaintext: never, _opts: never): unknown => ({}),
    }
    // @ts-expect-error — `encrypt` returning `unknown` does not satisfy the
    // factory's `ChainableOperation<Encrypted>` client contract.
    createEncryptionOperatorsV3(erased)
  })
})
