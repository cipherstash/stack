import { type Result, withResult } from '@byteslice/result'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { LockContext } from '../../identify'
import type { Client, Decrypted } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import {
  bulkDecryptModels,
  bulkDecryptModelsWithLockContext,
} from '../model-helpers'
import { ProtectOperation } from './base-operation'

export class BulkDecryptModelsOperation<
  T extends Record<string, unknown>,
> extends ProtectOperation<Decrypted<T>[]> {
  private client: Client
  private models: T[]

  constructor(client: Client, models: T[]) {
    super()
    this.client = client
    this.models = models
  }

  public withLockContext(
    lockContext: LockContext,
  ): BulkDecryptModelsOperationWithLockContext<T> {
    return new BulkDecryptModelsOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Decrypted<T>[], ProtectError>> {
    logger.debug('Bulk decrypting models WITHOUT a lock context')

    return await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return await bulkDecryptModels<T>(this.models, this.client, auditData)
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.DecryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
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
> extends ProtectOperation<Decrypted<T>[]> {
  private operation: BulkDecryptModelsOperation<T>
  private lockContext: LockContext

  constructor(
    operation: BulkDecryptModelsOperation<T>,
    lockContext: LockContext,
  ) {
    super()
    this.operation = operation
    this.lockContext = lockContext
  }

  public async execute(): Promise<Result<Decrypted<T>[], ProtectError>> {
    return await withResult(
      async () => {
        const { client, models } = this.operation.getOperation()

        logger.debug('Bulk decrypting models WITH a lock context')

        if (!client) {
          throw noClientError()
        }

        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
        }

        const auditData = this.getAuditData()

        return await bulkDecryptModelsWithLockContext<T>(
          models,
          client,
          context.data,
          auditData,
        )
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.DecryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
