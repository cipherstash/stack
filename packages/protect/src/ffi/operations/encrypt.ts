import { type Result, withResult } from '@byteslice/result'
import {
  encrypt as ffiEncrypt,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'
import type {
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
  ProtectValue,
} from '@cipherstash/schema'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { LockContext } from '../../identify'
import type { Client, Encrypted, EncryptOptions } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import { ProtectOperation } from './base-operation'

export class EncryptOperation extends ProtectOperation<Encrypted> {
  private client: Client
  private plaintext: JsPlaintext | null
  private column: ProtectColumn | ProtectValue
  private table: ProtectTable<ProtectTableColumn>

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

  public async execute(): Promise<Result<Encrypted, ProtectError>> {
    logger.debug('Encrypting data WITHOUT a lock context', {
      column: this.column.getName(),
      table: this.table.tableName,
    })

    return await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.plaintext === null) {
          return null
        }

        if (
          typeof this.plaintext === 'number' &&
          Number.isNaN(this.plaintext)
        ) {
          throw new Error('[protect]: Cannot encrypt NaN value')
        }

        if (
          typeof this.plaintext === 'number' &&
          !Number.isFinite(this.plaintext)
        ) {
          throw new Error('[protect]: Cannot encrypt Infinity value')
        }

        const { metadata } = this.getAuditData()

        return await ffiEncrypt(this.client, {
          plaintext: this.plaintext,
          column: this.column.getName(),
          table: this.table.tableName,
          unverifiedContext: metadata,
        })
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }

  public getOperation(): {
    client: Client
    plaintext: JsPlaintext | null
    column: ProtectColumn | ProtectValue
    table: ProtectTable<ProtectTableColumn>
  } {
    return {
      client: this.client,
      plaintext: this.plaintext,
      column: this.column,
      table: this.table,
    }
  }
}

export class EncryptOperationWithLockContext extends ProtectOperation<Encrypted> {
  private operation: EncryptOperation
  private lockContext: LockContext

  constructor(operation: EncryptOperation, lockContext: LockContext) {
    super()
    this.operation = operation
    this.lockContext = lockContext
  }

  public async execute(): Promise<Result<Encrypted, ProtectError>> {
    return await withResult(
      async () => {
        const { client, plaintext, column, table } =
          this.operation.getOperation()

        logger.debug('Encrypting data WITH a lock context', {
          column: column,
          table: table,
        })

        if (!client) {
          throw noClientError()
        }

        if (plaintext === null) {
          return null
        }

        const { metadata } = this.getAuditData()
        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
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
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
