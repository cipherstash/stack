import { type Result, withResult } from '@byteslice/result'
import {
  decrypt as ffiDecrypt,
  type JsPlaintext,
} from '@cipherstash/protect-ffi'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { LockContext } from '../../identify'
import type { Client, Encrypted } from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import { ProtectOperation } from './base-operation'

/**
 * Decrypts an encrypted payload using the provided client.
 * This is the type returned by the {@link ProtectClient.decrypt | decrypt} method of the {@link ProtectClient}.
 */
export class DecryptOperation extends ProtectOperation<JsPlaintext | null> {
  private client: Client
  private encryptedData: Encrypted

  constructor(client: Client, encryptedData: Encrypted) {
    super()
    this.client = client
    this.encryptedData = encryptedData
  }

  public withLockContext(
    lockContext: LockContext,
  ): DecryptOperationWithLockContext {
    return new DecryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<JsPlaintext | null, ProtectError>> {
    return await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.encryptedData === null) {
          return null
        }

        const { metadata } = this.getAuditData()

        logger.debug('Decrypting data WITHOUT a lock context', {
          metadata,
        })

        return await ffiDecrypt(this.client, {
          ciphertext: this.encryptedData,
          unverifiedContext: metadata,
        })
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
    encryptedData: Encrypted
    auditData?: Record<string, unknown>
  } {
    return {
      client: this.client,
      encryptedData: this.encryptedData,
      auditData: this.getAuditData(),
    }
  }
}

export class DecryptOperationWithLockContext extends ProtectOperation<JsPlaintext | null> {
  private operation: DecryptOperation
  private lockContext: LockContext

  constructor(operation: DecryptOperation, lockContext: LockContext) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<JsPlaintext | null, ProtectError>> {
    return await withResult(
      async () => {
        const { client, encryptedData } = this.operation.getOperation()

        if (!client) {
          throw noClientError()
        }

        if (encryptedData === null) {
          return null
        }

        const { metadata } = this.getAuditData()

        logger.debug('Decrypting data WITH a lock context', {
          metadata,
        })

        const context = await this.lockContext.getLockContext()

        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
        }

        return await ffiDecrypt(client, {
          ciphertext: encryptedData,
          unverifiedContext: metadata,
          lockContext: context.data.context,
          serviceToken: context.data.ctsToken,
        })
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.DecryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
