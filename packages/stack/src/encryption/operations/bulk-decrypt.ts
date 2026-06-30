import { type Result, withResult } from '@byteslice/result'
import {
  type Encrypted as CipherStashEncrypted,
  type DecryptResult,
  decryptBulkFallible,
} from '@cipherstash/protect-ffi'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type Context,
  type LockContextInput,
  resolveLockContext,
} from '@/identity'
import type { BulkDecryptedData, BulkDecryptPayload, Client } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

// Drops nulls so they don't reach protect-ffi's bulk decrypt. The
// dropped positions are re-inserted as null in `mapDecryptedDataToResult`.
const createDecryptPayloads = (
  encryptedPayloads: BulkDecryptPayload,
  lockContext?: Context,
) => {
  return encryptedPayloads
    .filter(({ data }) => data !== null)
    .map(({ id, data }) => ({
      id,
      ciphertext: data as CipherStashEncrypted,
      ...(lockContext && { lockContext }),
    }))
}

const createNullResult = (
  encryptedPayloads: BulkDecryptPayload,
): BulkDecryptedData => encryptedPayloads.map(({ id }) => ({ id, data: null }))

const mapDecryptedDataToResult = (
  encryptedPayloads: BulkDecryptPayload,
  decryptedData: DecryptResult[],
): BulkDecryptedData => {
  const result: BulkDecryptedData = new Array(encryptedPayloads.length)
  let decryptedIndex = 0
  for (let i = 0; i < encryptedPayloads.length; i++) {
    if (encryptedPayloads[i].data === null) {
      result[i] = { id: encryptedPayloads[i].id, data: null }
    } else {
      const decryptResult = decryptedData[decryptedIndex]
      if ('error' in decryptResult) {
        result[i] = { id: encryptedPayloads[i].id, error: decryptResult.error }
      } else {
        result[i] = { id: encryptedPayloads[i].id, data: decryptResult.data }
      }
      decryptedIndex++
    }
  }
  return result
}

export class BulkDecryptOperation extends EncryptionOperation<BulkDecryptedData> {
  private client: Client
  private encryptedPayloads: BulkDecryptPayload

  constructor(client: Client, encryptedPayloads: BulkDecryptPayload) {
    super()
    this.client = client
    this.encryptedPayloads = encryptedPayloads
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): BulkDecryptOperationWithLockContext {
    return new BulkDecryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<BulkDecryptedData, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'bulkDecrypt',
      count: this.encryptedPayloads?.length ?? 0,
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()
        if (!this.encryptedPayloads || this.encryptedPayloads.length === 0)
          return []

        const nonNullPayloads = createDecryptPayloads(this.encryptedPayloads)

        if (nonNullPayloads.length === 0) {
          return createNullResult(this.encryptedPayloads)
        }

        const { metadata } = this.getAuditData()

        const decryptedData = await decryptBulkFallible(this.client, {
          ciphertexts: nonNullPayloads,
          unverifiedContext: metadata,
        })

        return mapDecryptedDataToResult(this.encryptedPayloads, decryptedData)
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
    encryptedPayloads: BulkDecryptPayload
  } {
    return {
      client: this.client,
      encryptedPayloads: this.encryptedPayloads,
    }
  }
}

export class BulkDecryptOperationWithLockContext extends EncryptionOperation<BulkDecryptedData> {
  private operation: BulkDecryptOperation
  private lockContext: LockContextInput

  constructor(operation: BulkDecryptOperation, lockContext: LockContextInput) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<BulkDecryptedData, EncryptionError>> {
    const { client, encryptedPayloads } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'bulkDecrypt',
      count: encryptedPayloads?.length ?? 0,
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) throw noClientError()
        if (!encryptedPayloads || encryptedPayloads.length === 0) return []

        const lockContext = resolveLockContext(this.lockContext)

        const nonNullPayloads = createDecryptPayloads(
          encryptedPayloads,
          lockContext,
        )

        if (nonNullPayloads.length === 0) {
          return createNullResult(encryptedPayloads)
        }

        const { metadata } = this.getAuditData()

        const decryptedData = await decryptBulkFallible(client, {
          ciphertexts: nonNullPayloads,
          unverifiedContext: metadata,
        })

        return mapDecryptedDataToResult(encryptedPayloads, decryptedData)
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
