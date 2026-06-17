import { type Result, withResult } from '@byteslice/result'
import {
  encrypt as ffiEncrypt,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { LockContext } from '@/identity'
import type {
  EncryptedColumn,
  EncryptedField,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'
import type { Client, Encrypted, EncryptOptions } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class EncryptOperation extends EncryptionOperation<Encrypted> {
  private client: Client
  // Internally widened to allow null so the runtime guard below can
  // short-circuit. The public `Encryption.encrypt()` signature still
  // rejects null at the type layer; this is defense in depth for callers
  // that reach this class through casts or dynamic field walking.
  private plaintext: JsPlaintext | null
  private column: EncryptedColumn | EncryptedField
  private table: EncryptedTable<EncryptedTableColumn>

  constructor(
    client: Client,
    plaintext: JsPlaintext | null,
    opts: EncryptOptions,
  ) {
    super()
    this.client = client
    this.plaintext = plaintext
    this.column = opts.column
    this.table = opts.table
  }

  public withLockContext(
    lockContext: LockContext,
  ): EncryptOperationWithLockContext {
    return new EncryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Encrypted, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: this.table.tableName,
      column: this.column.getName(),
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.plaintext === null) {
          // Defense in depth: the public `Encryption.encrypt()` signature
          // rejects null, but null can still arrive here via casts or
          // dynamic field walking. Return null directly so the result
          // matches DB NULL semantics rather than encrypting JSON null
          // into a SteVec. The cast acknowledges the type-narrow
          // contract at the public boundary.
          return null as unknown as Encrypted
        }

        if (
          typeof this.plaintext === 'number' &&
          Number.isNaN(this.plaintext)
        ) {
          throw new Error('[encryption]: Cannot encrypt NaN value')
        }

        if (
          typeof this.plaintext === 'number' &&
          !Number.isFinite(this.plaintext)
        ) {
          throw new Error('[encryption]: Cannot encrypt Infinity value')
        }

        const { metadata } = this.getAuditData()

        return await ffiEncrypt(this.client, {
          plaintext: this.plaintext,
          column: this.column.getName(),
          table: this.table.tableName,
          unverifiedContext: metadata,
        })
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

  public getOperation(): {
    client: Client
    plaintext: JsPlaintext | null
    column: EncryptedColumn | EncryptedField
    table: EncryptedTable<EncryptedTableColumn>
  } {
    return {
      client: this.client,
      plaintext: this.plaintext,
      column: this.column,
      table: this.table,
    }
  }
}

export class EncryptOperationWithLockContext extends EncryptionOperation<Encrypted> {
  private operation: EncryptOperation
  private lockContext: LockContext

  constructor(operation: EncryptOperation, lockContext: LockContext) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<Encrypted, EncryptionError>> {
    const { client, plaintext, column, table } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: table.tableName,
      column: column.getName(),
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }

        if (plaintext === null) {
          return null as unknown as Encrypted
        }

        const { metadata } = this.getAuditData()
        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[encryption]: ${context.failure.message}`)
        }

        return await ffiEncrypt(client, {
          plaintext,
          column: column.getName(),
          table: table.tableName,
          lockContext: context.data.context,
          serviceToken: context.data.ctsToken,
          unverifiedContext: metadata,
        })
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
