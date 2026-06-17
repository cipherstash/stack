import { type Result, withResult } from '@byteslice/result'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { LockContext } from '@/identity'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { Client } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import {
  bulkEncryptModels,
  bulkEncryptModelsWithLockContext,
} from '../helpers/model-helpers'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class BulkEncryptModelsOperation<
  T extends Record<string, unknown>,
> extends EncryptionOperation<T[]> {
  private client: Client
  private models: Record<string, unknown>[]
  private table: EncryptedTable<EncryptedTableColumn>

  constructor(
    client: Client,
    models: Record<string, unknown>[],
    table: EncryptedTable<EncryptedTableColumn>,
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

  public async execute(): Promise<Result<T[], EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'bulkEncryptModels',
      table: this.table.tableName,
      count: this.models.length,
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return (await bulkEncryptModels(
          this.models,
          this.table,
          this.client,
          auditData,
        )) as T[]
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
    models: Record<string, unknown>[]
    table: EncryptedTable<EncryptedTableColumn>
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
> extends EncryptionOperation<T[]> {
  private operation: BulkEncryptModelsOperation<T>
  private lockContext: LockContext

  constructor(
    operation: BulkEncryptModelsOperation<T>,
    lockContext: LockContext,
  ) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<T[], EncryptionError>> {
    const { client, models, table } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'bulkEncryptModels',
      table: table.tableName,
      count: models.length,
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }

        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[encryption]: ${context.failure.message}`)
        }

        const auditData = this.getAuditData()

        return (await bulkEncryptModelsWithLockContext(
          models,
          table,
          client,
          context.data,
          auditData,
        )) as T[]
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
