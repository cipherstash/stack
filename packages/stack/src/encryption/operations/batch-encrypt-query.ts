import { type Result, withResult } from '@byteslice/result'
import type {
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
} from '@cipherstash/protect-ffi'
import {
  encryptQueryBulk as ffiEncryptQueryBulk,
  type JsPlaintext,
  type QueryPayload,
} from '@cipherstash/protect-ffi'
import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type Context,
  type LockContextInput,
  resolveLockContext,
} from '@/identity'
import type { Client, EncryptedQueryResult, ScalarQueryTerm } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '../helpers/validation'
import { noClientError } from '../index'
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
  encryptedValues: (CipherStashEncrypted | CipherStashEncryptedQuery)[],
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

export class BatchEncryptQueryOperation extends EncryptionOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
    private terms: readonly ScalarQueryTerm[],
  ) {
    super()
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): BatchEncryptQueryOperationWithLockContext {
    return new BatchEncryptQueryOperationWithLockContext(
      this.client,
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

        const encrypted = await ffiEncryptQueryBulk(this.client, {
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

export class BatchEncryptQueryOperationWithLockContext extends EncryptionOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
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

        const encrypted = await ffiEncryptQueryBulk(this.client, {
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
