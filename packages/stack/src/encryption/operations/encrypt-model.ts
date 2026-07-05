import { type Result, withResult } from '@byteslice/result'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { type LockContextInput, resolveLockContext } from '@/identity'
import type { BuildableTable, Client } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import {
  encryptModelFields,
  encryptModelFieldsWithLockContext,
} from '../helpers/model-helpers'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class EncryptModelOperation<
  T extends Record<string, unknown>,
> extends EncryptionOperation<T> {
  private client: Client
  private model: Record<string, unknown>
  private table: BuildableTable

  constructor(
    client: Client,
    model: Record<string, unknown>,
    table: BuildableTable,
  ) {
    super()
    this.client = client
    this.model = model
    this.table = table
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): EncryptModelOperationWithLockContext<T> {
    return new EncryptModelOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<T, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'encryptModel',
      table: this.table.tableName,
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return (await encryptModelFields(
          this.model,
          this.table,
          this.client,
          auditData,
        )) as T
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
    model: Record<string, unknown>
    table: BuildableTable
  } {
    return {
      client: this.client,
      model: this.model,
      table: this.table,
    }
  }
}

export class EncryptModelOperationWithLockContext<
  T extends Record<string, unknown>,
> extends EncryptionOperation<T> {
  private operation: EncryptModelOperation<T>
  private lockContext: LockContextInput

  constructor(
    operation: EncryptModelOperation<T>,
    lockContext: LockContextInput,
  ) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<T, EncryptionError>> {
    const { client, model, table } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'encryptModel',
      table: table.tableName,
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }

        const context = resolveLockContext(this.lockContext)

        const auditData = this.getAuditData()

        return (await encryptModelFieldsWithLockContext(
          model,
          table,
          client,
          context,
          auditData,
        )) as T
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
