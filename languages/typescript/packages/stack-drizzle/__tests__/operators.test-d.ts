import type { Result } from '@byteslice/result'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
import type { EncryptionError } from '@cipherstash/stack/errors'
import type { LockContext } from '@cipherstash/stack/identity'
import type { EncryptedQueryResult } from '@cipherstash/stack/types'
import type { EncryptionClient } from '@cipherstash/stack/v3'
import { describe, expectTypeOf, it } from 'vitest'
import { createEncryptionOperators } from '../src/index.js'

/**
 * Static regression guard for M1: `createEncryptionOperators` must accept every
 * client shape a caller can hand it, none requiring a cast —
 *
 * 1. the DEFAULTED `EncryptionClient`. Its schema-tuple parameter defaults to
 *    `readonly AnyV3Table[]`, so `EncryptionClient` and
 *    `EncryptionClient<readonly AnyV3Table[]>` are the SAME type — asserting
 *    both would be one assertion written twice, which is why only one appears.
 * 2. `EncryptionClient<readonly [typeof users]>` — the distinct instantiation
 *    `Encryption({ schemas })` actually returns, narrowed to exactly the tables
 *    it was given. This is the documented
 *    `createEncryptionOperators(await Encryption({ schemas }))` usage.
 * 3. a hand-rolled `{ encryptQuery, encrypt }` double. This is the case with
 *    real teeth: the two client instantiations above are mutually assignable
 *    (the interface's members are declared method-style, so TypeScript relates
 *    them bivariantly), but the double is NOT assignable to `EncryptionClient`
 *    — it is missing `encryptModel`, `decrypt`, `decryptModel` and five more.
 *    So it is the double, not schema-tuple width, that forces the factory's
 *    parameter to stay structural (`OperandEncryptionClient`) rather than
 *    naming `EncryptionClient` nominally.
 *
 * Every operand is now encrypted with `encryptQuery` (#622), so the operand
 * client contract is `encryptQuery` in both its single and batch forms; the
 * doubles model that. Lives in a `*.test-d.ts` so it is inside the existing
 * typecheck scope without dragging the loose-typed runtime suites in.
 */
describe('createEncryptionOperators - client parameter (M1)', () => {
  const users = encryptedTable('users', {
    email: types.TextSearch('email'),
    age: types.IntegerOrd('age'),
  })

  // A query operation resolving `Result<T, …>` — the surface the factory drives.
  type QueryOp<T> = {
    withLockContext(lc: LockContext): QueryOp<T>
    audit(cfg: AuditConfig): QueryOp<T>
    then: PromiseLike<Result<T, EncryptionError>>['then']
  }

  it('accepts the defaulted EncryptionClient', () => {
    expectTypeOf(createEncryptionOperators).toBeCallableWith(
      {} as EncryptionClient,
    )
  })

  it('accepts a client built for a concrete schema tuple', () => {
    expectTypeOf(createEncryptionOperators).toBeCallableWith(
      {} as EncryptionClient<readonly [typeof users]>,
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
