import { type Result, withResult } from '@byteslice/result'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { LockContext } from '../../identify'
import type { Client, Decrypted } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import {
  decryptModelFields,
  decryptModelFieldsWithLockContext,
} from '../model-helpers'
import { ProtectOperation } from './base-operation'

export class DecryptModelOperation<
  T extends Record<string, unknown>,
> extends ProtectOperation<Decrypted<T>> {
  private client: Client
  private model: T

  constructor(client: Client, model: T) {
    super()
    this.client = client
    this.model = model
  }

  public withLockContext(
    lockContext: LockContext,
  ): DecryptModelOperationWithLockContext<T> {
    return new DecryptModelOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Decrypted<T>, ProtectError>> {
    logger.debug('Decrypting model WITHOUT a lock context')

    return await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return await decryptModelFields<T>(this.model, this.client, auditData)
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
    model: T
  } {
    return {
      client: this.client,
      model: this.model,
    }
  }
}

export class DecryptModelOperationWithLockContext<
  T extends Record<string, unknown>,
> extends ProtectOperation<Decrypted<T>> {
  private operation: DecryptModelOperation<T>
  private lockContext: LockContext

  constructor(operation: DecryptModelOperation<T>, lockContext: LockContext) {
    super()
    this.operation = operation
    this.lockContext = lockContext
  }

  public async execute(): Promise<Result<Decrypted<T>, ProtectError>> {
    return await withResult(
      async () => {
        const { client, model } = this.operation.getOperation()

        logger.debug('Decrypting model WITH a lock context')

        if (!client) {
          throw noClientError()
        }

        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
        }

        const auditData = this.getAuditData()

        return await decryptModelFieldsWithLockContext<T>(
          model,
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
