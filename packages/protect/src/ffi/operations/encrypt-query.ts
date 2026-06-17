import { type Result, withResult } from '@byteslice/result'
import {
  encryptQuery as ffiEncryptQuery,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import { formatEncryptedResult } from '../../helpers'
import type { LockContext } from '../../identify'
import type {
  Client,
  EncryptedQueryResult,
  EncryptQueryOptions,
} from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertValueIndexCompatibility,
  validateNumericValue,
} from '../helpers/validation'
import { noClientError } from '../index'
import { ProtectOperation } from './base-operation'

/**
 * @internal Use {@link ProtectClient.encryptQuery} instead.
 */
export class EncryptQueryOperation extends ProtectOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null,
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

  public async execute(): Promise<Result<EncryptedQueryResult, ProtectError>> {
    logger.debug('Encrypting query', {
      column: this.opts.column.getName(),
      table: this.opts.table.tableName,
      queryType: this.opts.queryType,
    })

    if (this.plaintext === null || this.plaintext === undefined) {
      return { data: null }
    }

    const validationError = validateNumericValue(this.plaintext)
    if (validationError?.failure) {
      return { failure: validationError.failure }
    }

    return await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          this.plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          this.plaintext,
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
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }

  public getOperation() {
    return { client: this.client, plaintext: this.plaintext, ...this.opts }
  }
}

/**
 * @internal Use {@link ProtectClient.encryptQuery} with `.withLockContext()` instead.
 */
export class EncryptQueryOperationWithLockContext extends ProtectOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private plaintext: JsPlaintext | null,
    private opts: EncryptQueryOptions,
    private lockContext: LockContext,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<Result<EncryptedQueryResult, ProtectError>> {
    if (this.plaintext === null || this.plaintext === undefined) {
      return { data: null }
    }

    const validationError = validateNumericValue(this.plaintext)
    if (validationError?.failure) {
      return { failure: validationError.failure }
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

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          this.plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          this.plaintext,
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
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
