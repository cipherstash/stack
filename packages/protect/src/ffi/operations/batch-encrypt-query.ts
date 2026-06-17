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
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import { formatEncryptedResult } from '../../helpers'
import type { Context, LockContext } from '../../identify'
import type { Client, EncryptedQueryResult, ScalarQueryTerm } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '../helpers/validation'
import { noClientError } from '../index'
import { ProtectOperation } from './base-operation'

/**
 * Separates null/undefined values from non-null terms in the input array.
 * Returns a set of indices where values are null/undefined and an array of non-null terms with their original indices.
 */
function filterNullTerms(terms: readonly ScalarQueryTerm[]): {
  nullIndices: Set<number>
  nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[]
} {
  const nullIndices = new Set<number>()
  const nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[] = []

  terms.forEach((term, index) => {
    if (term.value === null || term.value === undefined) {
      nullIndices.add(index)
    } else {
      nonNullTerms.push({ term, originalIndex: index })
    }
  })

  return { nullIndices, nonNullTerms }
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
 * Reconstructs the results array with nulls in their original positions.
 * Non-null encrypted values are placed at their original indices.
 * Applies formatting based on term.returnType.
 */
function assembleResults(
  totalLength: number,
  encryptedValues: (CipherStashEncrypted | CipherStashEncryptedQuery)[],
  nonNullTerms: { term: ScalarQueryTerm; originalIndex: number }[],
): EncryptedQueryResult[] {
  const results: EncryptedQueryResult[] = new Array(totalLength).fill(null)

  // Fill in encrypted values at their original positions, applying formatting
  nonNullTerms.forEach(({ term, originalIndex }, i) => {
    const encrypted = encryptedValues[i]

    results[originalIndex] = formatEncryptedResult(encrypted, term.returnType)
  })

  return results
}

/**
 * @internal Use {@link ProtectClient.encryptQuery} with array input instead.
 */
export class BatchEncryptQueryOperation extends ProtectOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
    private terms: readonly ScalarQueryTerm[],
  ) {
    super()
  }

  public withLockContext(
    lockContext: LockContext,
  ): BatchEncryptQueryOperationWithLockContext {
    return new BatchEncryptQueryOperationWithLockContext(
      this.client,
      this.terms,
      lockContext,
      this.auditMetadata,
    )
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult[], ProtectError>
  > {
    logger.debug('Encrypting query terms', { count: this.terms.length })

    if (this.terms.length === 0) {
      return { data: [] }
    }

    const { nullIndices, nonNullTerms } = filterNullTerms(this.terms)

    if (nonNullTerms.length === 0) {
      return { data: this.terms.map(() => null) }
    }

    return await withResult(
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
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}

/**
 * @internal Use {@link ProtectClient.encryptQuery} with array input and `.withLockContext()` instead.
 */
export class BatchEncryptQueryOperationWithLockContext extends ProtectOperation<
  EncryptedQueryResult[]
> {
  constructor(
    private client: Client,
    private terms: readonly ScalarQueryTerm[],
    private lockContext: LockContext,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult[], ProtectError>
  > {
    logger.debug('Encrypting query terms with lock context', {
      count: this.terms.length,
    })

    if (this.terms.length === 0) {
      return { data: [] }
    }

    // Check for all-null terms BEFORE fetching lockContext to avoid unnecessary network call
    const { nullIndices, nonNullTerms } = filterNullTerms(this.terms)

    if (nonNullTerms.length === 0) {
      return { data: this.terms.map(() => null) }
    }

    const lockContextResult = await this.lockContext.getLockContext()
    if (lockContextResult.failure) {
      return { failure: lockContextResult.failure }
    }

    const { ctsToken, context } = lockContextResult.data

    return await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = nonNullTerms.map(({ term }) =>
          buildQueryPayload(term, context),
        )

        const encrypted = await ffiEncryptQueryBulk(this.client, {
          queries,
          serviceToken: ctsToken,
          unverifiedContext: metadata,
        })

        return assembleResults(this.terms.length, encrypted, nonNullTerms)
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
