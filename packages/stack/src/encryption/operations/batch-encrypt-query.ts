import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { Context, LockContext } from '@/identity'
import type { Client, EncryptedQueryResult, ScalarQueryTerm } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { type Result, withResult } from '@byteslice/result'
import {
  type QueryPayload,
  encryptQueryBulk as ffiEncryptQueryBulk,
} from '@cipherstash/protect-ffi'
import type {
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
} from '@cipherstash/protect-ffi'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValidNumericValue,
  assertValueIndexCompatibility,
} from '../helpers/validation'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

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
    plaintext: term.value,
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
 * Maps encrypted values to formatted results based on term.returnType.
 */
function assembleResults(
  terms: readonly ScalarQueryTerm[],
  encryptedValues: (CipherStashEncrypted | CipherStashEncryptedQuery)[],
): EncryptedQueryResult[] {
  return terms.map((term, i) =>
    formatEncryptedResult(encryptedValues[i], term.returnType),
  )
}

/**
 * @internal Use {@link EncryptionClient.encryptQuery} with array input instead.
 */
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

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = this.terms.map((term) =>
          buildQueryPayload(term),
        )

        const encrypted = await ffiEncryptQueryBulk(this.client, {
          queries,
          unverifiedContext: metadata,
        })

        return assembleResults(this.terms, encrypted)
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
 * @internal Use {@link EncryptionClient.encryptQuery} with array input and `.withLockContext()` instead.
 */
export class BatchEncryptQueryOperationWithLockContext extends EncryptionOperation<
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

    const lockContextResult = await this.lockContext.getLockContext()
    if (lockContextResult.failure) {
      log.emit()
      return { failure: lockContextResult.failure }
    }

    const { ctsToken, context } = lockContextResult.data

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const queries: QueryPayload[] = this.terms.map((term) =>
          buildQueryPayload(term, context),
        )

        const encrypted = await ffiEncryptQueryBulk(this.client, {
          queries,
          serviceToken: ctsToken,
          unverifiedContext: metadata,
        })

        return assembleResults(this.terms, encrypted)
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
