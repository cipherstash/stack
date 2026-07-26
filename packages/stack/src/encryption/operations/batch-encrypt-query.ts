import { type Result, withResult } from '@byteslice/result'
import type { JsPlaintext, QueryPayload } from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { Context } from '@/identity'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type { Client, EncryptedQueryResult, ScalarQueryTerm } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertMatchNeedleQueryable,
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '../helpers/validation'
import { noClientError } from '../no-client-error'
import { EncryptionOperation } from './base-operation'

// Separates null/undefined values from non-null terms in the input array
// so they bypass the FFI call. Original indices are tracked so the
// reassembled result preserves position.
function filterNullTerms(terms: readonly ScalarQueryTerm[]): {
  nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[]
} {
  const nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[] = []
  terms.forEach((term, index) => {
    if (term.value !== null && term.value !== undefined) {
      nonNullTerms.push({ term, originalIndex: index })
    }
  })
  return { nonNullTerms }
}

/**
 * Validates and transforms a single term into a QueryPayload.
 * Throws an error if the value is NaN or Infinity.
 * Optionally includes lockContext if provided.
 */
function buildQueryPayload(
  term: ScalarQueryTerm,
  lockContext?: Context,
): QueryPayload {
  assertValidNumericValue(term.value)

  const { indexType, queryOp } = resolveIndexType(
    term.column,
    term.queryType,
    term.value,
  )

  // Validate value/index compatibility
  assertValueIndexCompatibility(term.value, indexType, term.column.getName())
  assertMatchNeedleQueryable(term.value, indexType, term.column)

  const payload: QueryPayload = {
    plaintext: term.value as JsPlaintext,
    column: term.column.getName(),
    table: term.table.tableName,
    indexType,
    queryOp,
  }

  if (lockContext != null) {
    payload.lockContext = lockContext
  }

  return payload
}

/**
 * Reassembles the result array, slotting null at the original indices of
 * filtered-out terms and formatting encrypted values for non-null terms.
 */
function assembleResults(
  totalLength: number,
  // Typed as the FFI bulk-query return so it tracks scalar, SteVec containment,
  // selector-hash, value-selector, and selector-ordering query shapes.
  encryptedValues: Awaited<ReturnType<CryptoBackend['encryptQueryBulk']>>,
  nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[],
): EncryptedQueryResult[] {
  const results: EncryptedQueryResult[] = new Array(totalLength).fill(null)
  nonNullTerms.forEach(({ term, originalIndex }, i) => {
    results[originalIndex] = formatEncryptedResult(
      encryptedValues[i],
      term.returnType,
    )
  })
  return results
}

/**
 * Encrypts many query terms in one ZeroKMS round trip.
 *
 * Returned by `Encryption.encryptQuery()` when given an array of terms. Both a
 * builder and a promise: chain `.audit()` / `.withLockContext()`, then `await`
 * for a `Result` — see {@link EncryptionOperation}.
 *
 * Terms are independent: each names its own table, column, and query type, so
 * one batch can span columns and tables. This is the call to reach for when
 * building a `WHERE` clause with several encrypted predicates — one round trip
 * instead of one per predicate.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry and on
 * `@cipherstash/stack/wasm-inline` (cipherstash/stack#798).
 *
 * ## Nulls and position
 *
 * Null and undefined terms are filtered out before the FFI call and re-slotted
 * as `null` at their original indices, so the result always lines up
 * index-for-index with the input. That depends on
 * {@link CryptoBackend.encryptQueryBulk} returning terms in the order it was
 * given them.
 */
export class BatchEncryptQueryOperation extends EncryptionOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
    private backend: CryptoBackend,
    private terms: readonly ScalarQueryTerm[],
  ) {
    super()
  }

  /**
   * Derive every term in the batch under an identity claim.
   *
   * Returns a new operation rather than mutating this one; audit metadata
   * already set is passed across.
   *
   * @param lockContext The claim the target values were encrypted under. It
   * applies to the whole batch — terms against columns bound to different
   * claims need separate calls.
   */
  public withLockContext(
    lockContext: LockContextInput,
  ): BatchEncryptQueryOperationWithLockContext {
    return new BatchEncryptQueryOperationWithLockContext(
      this.client,
      this.backend,
      this.terms,
      lockContext,
      this.auditMetadata,
    )
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult[], EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'batchEncryptQuery',
      count: this.terms.length,
      lockContext: false,
    })

    if (this.terms.length === 0) {
      log.emit()
      return { data: [] }
    }

    const { nonNullTerms } = filterNullTerms(this.terms)

    if (nonNullTerms.length === 0) {
      log.emit()
      return { data: this.terms.map(() => null) }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = nonNullTerms.map(({ term }) =>
          buildQueryPayload(term),
        )

        const encrypted = await this.backend.encryptQueryBulk(this.client, {
          queries,
          unverifiedContext: metadata,
        })

        return assembleResults(this.terms.length, encrypted, nonNullTerms)
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.EncryptionError,
          message: (error as Error).message,
          code: getErrorCode(error),
        }
      },
    )
    log.emit()
    return result
  }
}

/**
 * {@link BatchEncryptQueryOperation} deriving its terms under an identity
 * claim.
 *
 * Constructed by `BatchEncryptQueryOperation.withLockContext()`, not directly.
 *
 * Note where the context goes: {@link CryptoBackend.encryptQueryBulk} takes it
 * on each `QueryPayload`, not at the top level of the call, so it is threaded
 * through `buildQueryPayload`. Everything else is the same path as the unbound
 * operation.
 */
export class BatchEncryptQueryOperationWithLockContext extends EncryptionOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
    private backend: CryptoBackend,
    private terms: readonly ScalarQueryTerm[],
    private lockContext: LockContextInput,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult[], EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'batchEncryptQuery',
      count: this.terms.length,
      lockContext: true,
    })

    if (this.terms.length === 0) {
      log.emit()
      return { data: [] }
    }

    const { nonNullTerms } = filterNullTerms(this.terms)

    if (nonNullTerms.length === 0) {
      log.emit()
      return { data: this.terms.map(() => null) }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const context = resolveLockContext(this.lockContext)

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = nonNullTerms.map(({ term }) =>
          buildQueryPayload(term, context),
        )

        const encrypted = await this.backend.encryptQueryBulk(this.client, {
          queries,
          unverifiedContext: metadata,
        })

        return assembleResults(this.terms.length, encrypted, nonNullTerms)
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.EncryptionError,
          message: (error as Error).message,
          code: getErrorCode(error),
        }
      },
    )
    log.emit()
    return result
  }
}
