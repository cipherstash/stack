import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { LockContext } from '@/identity'
import type { Client, EncryptQueryOptions, EncryptedQueryResult } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { type Result, withResult } from '@byteslice/result'
import {
  type JsPlaintext,
  encryptQuery as ffiEncryptQuery,
} from '@cipherstash/protect-ffi'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValueIndexCompatibility,
  validateNumericValue,
} from '../helpers/validation'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

/**
 * @internal Use {@link EncryptionClient.encryptQuery} instead.
 */
export class EncryptQueryOperation extends EncryptionOperation<
  EncryptedQueryResult | null
> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null | undefined,
    private opts: EncryptQueryOptions,
  ) {
    super()
  }

  public withLockContext(
    lockContext: LockContext,
  ): EncryptQueryOperationWithLockContext {
    return new EncryptQueryOperationWithLockContext(
      this.client,
      this.plaintext,
      this.opts,
      lockContext,
      this.auditMetadata,
    )
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult | null, EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'encryptQuery',
      table: this.opts.table.tableName,
      column: this.opts.column.getName(),
      queryType: this.opts.queryType,
      lockContext: false,
    })

    if (this.plaintext === null || this.plaintext === undefined) {
      log.emit()
      return { data: null }
    }

    const validationError = validateNumericValue(this.plaintext)
    if (validationError?.failure) {
      log.emit()
      return { failure: validationError.failure }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          this.plaintext as JsPlaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          this.plaintext as JsPlaintext,
          indexType,
          this.opts.column.getName(),
        )

        const encrypted = await ffiEncryptQuery(this.client, {
          plaintext: this.plaintext as JsPlaintext,
          column: this.opts.column.getName(),
          table: this.opts.table.tableName,
          indexType,
          queryOp,
          unverifiedContext: metadata,
        })

        return formatEncryptedResult(encrypted, this.opts.returnType)
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

  public getOperation() {
    return { client: this.client, plaintext: this.plaintext, ...this.opts }
  }
}

/**
 * @internal Use {@link EncryptionClient.encryptQuery} with `.withLockContext()` instead.
 */
export class EncryptQueryOperationWithLockContext extends EncryptionOperation<
  EncryptedQueryResult | null
> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null | undefined,
    private opts: EncryptQueryOptions,
    private lockContext: LockContext,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult | null, EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'encryptQuery',
      table: this.opts.table.tableName,
      column: this.opts.column.getName(),
      queryType: this.opts.queryType,
      lockContext: true,
    })

    if (this.plaintext === null || this.plaintext === undefined) {
      log.emit()
      return { data: null }
    }

    const validationError = validateNumericValue(this.plaintext)
    if (validationError?.failure) {
      log.emit()
      return { failure: validationError.failure }
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

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          this.plaintext as JsPlaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          this.plaintext as JsPlaintext,
          indexType,
          this.opts.column.getName(),
        )

        const encrypted = await ffiEncryptQuery(this.client, {
          plaintext: this.plaintext as JsPlaintext,
          column: this.opts.column.getName(),
          table: this.opts.table.tableName,
          indexType,
          queryOp,
          lockContext: context,
          serviceToken: ctsToken,
          unverifiedContext: metadata,
        })

        return formatEncryptedResult(encrypted, this.opts.returnType)
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
