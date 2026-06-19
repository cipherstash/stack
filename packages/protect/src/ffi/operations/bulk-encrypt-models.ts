import { type Result, withResult } from '@byteslice/result'
import type { ProtectTable, ProtectTableColumn } from '@cipherstash/schema'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { LockContext } from '../../identify'
import type { Client, Decrypted } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import {
  bulkEncryptModels,
  bulkEncryptModelsWithLockContext,
} from '../model-helpers'
import { ProtectOperation } from './base-operation'

export class BulkEncryptModelsOperation<
  T extends Record<string, unknown>,
> extends ProtectOperation<T[]> {
  private client: Client
  private models: Decrypted<T>[]
  private table: ProtectTable<ProtectTableColumn>

  constructor(
    client: Client,
    models: Decrypted<T>[],
    table: ProtectTable<ProtectTableColumn>,
  ) {
    super()
    this.client = client
    this.models = models
    this.table = table
  }

  public withLockContext(
    lockContext: LockContext,
  ): BulkEncryptModelsOperationWithLockContext<T> {
    return new BulkEncryptModelsOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<T[], ProtectError>> {
    logger.debug('Bulk encrypting models WITHOUT a lock context', {
      table: this.table.tableName,
    })

    return await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return await bulkEncryptModels<T>(
          this.models,
          this.table,
          this.client,
          auditData,
        )
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
    models: Decrypted<T>[]
    table: ProtectTable<ProtectTableColumn>
  } {
    return {
      client: this.client,
      models: this.models,
      table: this.table,
    }
  }
}

export class BulkEncryptModelsOperationWithLockContext<
  T extends Record<string, unknown>,
> extends ProtectOperation<T[]> {
  private operation: BulkEncryptModelsOperation<T>
  private lockContext: LockContext

  constructor(
    operation: BulkEncryptModelsOperation<T>,
    lockContext: LockContext,
  ) {
    super()
    this.operation = operation
    this.lockContext = lockContext
  }

  public async execute(): Promise<Result<T[], ProtectError>> {
    return await withResult(
      async () => {
        const { client, models, table } = this.operation.getOperation()

        logger.debug('Bulk encrypting models WITH a lock context', {
          table: table.tableName,
        })

        if (!client) {
          throw noClientError()
        }

        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
        }

        const auditData = this.getAuditData()

        return await bulkEncryptModelsWithLockContext<T>(
          models,
          table,
          client,
          context.data,
          auditData,
        )
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
