import type { Result } from '@byteslice/result'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { EncryptionError } from '@cipherstash/stack/errors'
import type { LockContext } from '@cipherstash/stack/identity'
import type { EncryptedQueryResult } from '@cipherstash/stack/types'
import type { EncryptionV3 } from '@cipherstash/stack/v3'
import { describe, expectTypeOf, it } from 'vitest'
import { createEncryptionOperators } from '../src/index.js'

/**
 * Static regression guard for M1: `createEncryptionOperators` must accept the
 * `TypedEncryptionClient` that `EncryptionV3` resolves to — the documented
 * `createEncryptionOperators(await EncryptionV3({ schemas }))` usage — as well
 * as the nominal `EncryptionClient` and a hand-rolled `{ encryptQuery }` double,
 * none requiring a cast. Typing the parameter to `EncryptionClient` (the
 * original bug) makes the first call below a compile error, which this suite
 * would then catch. Every operand is now encrypted with `encryptQuery` (#622),
 * so the operand client contract is `encryptQuery` in both its single and batch
 * forms; the doubles model that. Lives in a `*.test-d.ts` so it is inside the
 * existing typecheck scope without dragging the loose-typed runtime suites in.
 */
describe('createEncryptionOperators - client parameter (M1)', () => {
  type V3Client = Awaited<ReturnType<typeof EncryptionV3>>

  // A query operation resolving `Result<T, …>` — the surface the factory drives.
  type QueryOp<T> = {
    withLockContext(lc: LockContext): QueryOp<T>
    audit(cfg: AuditConfig): QueryOp<T>
    then: PromiseLike<Result<T, EncryptionError>>['then']
  }

  it('accepts the client EncryptionV3 returns with no cast', () => {
    expectTypeOf(createEncryptionOperators).toBeCallableWith({} as V3Client)
  })

  it('still accepts the nominal EncryptionClient', () => {
    expectTypeOf(createEncryptionOperators).toBeCallableWith(
      {} as EncryptionClient,
    )
  })

  it('accepts a minimal structural { encryptQuery } double', () => {
    // The double models what the real client returns for both encryptQuery forms:
    // an operation whose `then` resolves `Result<EncryptedQueryResult, …>` (single)
    // or `Result<EncryptedQueryResult[], …>` (batch), not `unknown`. That is the
    // point of the un-erasure — the factory reads `result.data` as a query term
    // (single) or an array of them (batch) rather than casting it. The single
    // implementation returns the intersection, so it satisfies both overloads.
    const double = {
      encryptQuery: (
        _valueOrTerms: never,
        _opts?: never,
      ): QueryOp<EncryptedQueryResult> & QueryOp<EncryptedQueryResult[]> =>
        ({}) as never,
      // Storage encryption — consumed only by the JSON selector RHS, but part of
      // the operand-client contract, so a structural double must supply it too.
      encrypt: (_value: never, _opts: never): QueryOp<unknown> => ({}) as never,
    }
    expectTypeOf(createEncryptionOperators).toBeCallableWith(double)
  })

  it('rejects an { encryptQuery } double that resolves `unknown` (the erasure regression)', () => {
    // The complement of the test above, and the one with teeth: `toBeCallableWith`
    // a correctly-typed double keeps passing even if the client contract
    // regressed to `unknown` (a correct value is assignable to `unknown`), so it
    // cannot catch re-erasure. This can. `encryptQuery` resolving `unknown` must
    // NOT satisfy the factory, whose contract resolves an `EncryptedQueryResult`;
    // if the erasure ever comes back, the `@ts-expect-error` goes unused and fails.
    const erased = {
      encryptQuery: (_valueOrTerms: never, _opts?: never): QueryOp<unknown> =>
        ({}) as never,
      // A correctly-typed `encrypt` so the ONLY reason this double is rejected is
      // the `encryptQuery`-resolves-`unknown` erasure — not a missing member.
      encrypt: (_value: never, _opts: never): QueryOp<unknown> => ({}) as never,
    }
    // @ts-expect-error — `encryptQuery` resolving `unknown` does not satisfy the
    // factory's `ChainableOperation<EncryptedQueryResult>` client contract.
    createEncryptionOperators(erased)
  })
})
