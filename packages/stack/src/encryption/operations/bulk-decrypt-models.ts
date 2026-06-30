import { type Result, withResult } from '@byteslice/result'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { type LockContextInput, resolveLockContext } from '@/identity'
import type { Client, Decrypted } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import {
  bulkDecryptModels,
  bulkDecryptModelsWithLockContext,
} from '../helpers/model-helpers'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class BulkDecryptModelsOperation<
  T extends Record<string, unknown>,
> extends EncryptionOperation<Decrypted<T>[]> {
  private client: Client
  private models: T[]

  constructor(client: Client, models: T[]) {
    super()
    this.client = client
    this.models = models
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): BulkDecryptModelsOperationWithLockContext<T> {
    return new BulkDecryptModelsOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Decrypted<T>[], EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'bulkDecryptModels',
      count: this.models.length,
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return await bulkDecryptModels<T>(this.models, this.client, auditData)
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.DecryptionError,
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
    models: T[]
  } {
    return {
      client: this.client,
      models: this.models,
    }
  }
}

export class BulkDecryptModelsOperationWithLockContext<
  T extends Record<string, unknown>,
> extends EncryptionOperation<Decrypted<T>[]> {
  private operation: BulkDecryptModelsOperation<T>
  private lockContext: LockContextInput

  constructor(
    operation: BulkDecryptModelsOperation<T>,
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

  public async execute(): Promise<Result<Decrypted<T>[], EncryptionError>> {
    const { client, models } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'bulkDecryptModels',
      count: models.length,
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }

        const context = resolveLockContext(this.lockContext)

        const auditData = this.getAuditData()

        return await bulkDecryptModelsWithLockContext<T>(
          models,
          client,
          context,
          auditData,
        )
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.DecryptionError,
          message: (error as Error).message,
          code: getErrorCode(error),
        }
      },
    )
    log.emit()
    return result
  }
}
