import { type Result, withResult } from '@byteslice/result'
import { getErrorCode } from '@/encryption/helpers/error-code'
import {
  type EncryptionError,
  EncryptionErrorTypes,
  toEncryptionError,
} from '@/errors'
import { type LockContextInput, resolveLockContext } from '@/identity'
import type { Client, Decrypted } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import {
  decryptModelFields,
  decryptModelFieldsWithLockContext,
} from '../helpers/model-helpers'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

export class DecryptModelOperation<
  T extends Record<string, unknown>,
> extends EncryptionOperation<Decrypted<T>> {
  private client: Client
  private model: T

  constructor(client: Client, model: T) {
    super()
    this.client = client
    this.model = model
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): DecryptModelOperationWithLockContext<T> {
    return new DecryptModelOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Decrypted<T>, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'decryptModel',
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        const auditData = this.getAuditData()

        return await decryptModelFields<T>(this.model, this.client, auditData)
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return toEncryptionError(
          EncryptionErrorTypes.DecryptionError,
          error,
          getErrorCode(error),
        )
      },
    )
    log.emit()
    return result
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
> extends EncryptionOperation<Decrypted<T>> {
  private operation: DecryptModelOperation<T>
  private lockContext: LockContextInput

  constructor(
    operation: DecryptModelOperation<T>,
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

  public async execute(): Promise<Result<Decrypted<T>, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'decryptModel',
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        const { client, model } = this.operation.getOperation()

        if (!client) {
          throw noClientError()
        }

        const context = resolveLockContext(this.lockContext)

        const auditData = this.getAuditData()

        return await decryptModelFieldsWithLockContext<T>(
          model,
          client,
          context,
          auditData,
        )
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return toEncryptionError(
          EncryptionErrorTypes.DecryptionError,
          error,
          getErrorCode(error),
        )
      },
    )
    log.emit()
    return result
  }
}
