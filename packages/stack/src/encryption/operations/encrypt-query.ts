import { type Result, withResult } from '@byteslice/result'
import {
  encryptQuery as ffiEncryptQuery,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'
import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { type LockContextInput, resolveLockContext } from '@/identity'
import type { Client, EncryptedQueryResult, EncryptQueryOptions } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValueIndexCompatibility,
  validateNumericValue,
} from '../helpers/validation'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class EncryptQueryOperation extends EncryptionOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null | undefined,
    private opts: EncryptQueryOptions,
  ) {
    super()
  }

  public withLockContext(
    lockContext: LockContextInput,
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
    Result<EncryptedQueryResult, EncryptionError>
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

    const plaintext: JsPlaintext = this.plaintext

    const validationError = validateNumericValue(plaintext)
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
          plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          plaintext,
          indexType,
          this.opts.column.getName(),
        )

        const encrypted = await ffiEncryptQuery(this.client, {
          plaintext,
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

export class EncryptQueryOperationWithLockContext extends EncryptionOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null | undefined,
    private opts: EncryptQueryOptions,
    private lockContext: LockContextInput,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult, EncryptionError>
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

    const plaintext: JsPlaintext = this.plaintext

    const validationError = validateNumericValue(plaintext)
    if (validationError?.failure) {
      log.emit()
      return { failure: validationError.failure }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const context = resolveLockContext(this.lockContext)

        const { metadata } = this.getAuditData()

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          plaintext,
          indexType,
          this.opts.column.getName(),
        )

        const encrypted = await ffiEncryptQuery(this.client, {
          plaintext,
          column: this.opts.column.getName(),
          table: this.opts.table.tableName,
          indexType,
          queryOp,
          lockContext: context,
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
