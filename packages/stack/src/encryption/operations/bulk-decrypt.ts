import { type Result, withResult } from '@byteslice/result'
import type {
  Encrypted as CipherStashEncrypted,
  DecryptResult,
} from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { Context } from '@/identity'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type { BulkDecryptedData, BulkDecryptPayload, Client } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../no-client-error'
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

/**
 * Decrypts many payloads in one ZeroKMS round trip.
 *
 * Returned by `Encryption.bulkDecrypt()`. Both a builder and a promise: chain
 * `.audit()` / `.withLockContext()`, then `await` for a `Result` — see
 * {@link EncryptionOperation}.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry and on
 * `@cipherstash/stack/wasm-inline` (cipherstash/stack#798).
 *
 * ## Two kinds of "no value", kept distinct
 *
 * - **Null input** — filtered out before the FFI call and re-inserted at its
 *   original index as `{ id, data: null }`. A NULL column reads back as NULL.
 * - **Failed decrypt** — comes back as `{ id, error }` for that item only.
 *   This uses {@link CryptoBackend.decryptBulkFallible}, so one unreadable row
 *   (wrong lock context, say) does not cost the caller the whole batch.
 *
 * Either way the result is the same length and order as the input, which
 * depends on the backend returning results in the order it was given them.
 */
export class BulkDecryptOperation extends EncryptionOperation<BulkDecryptedData> {
  private client: Client
  private backend: CryptoBackend
  private encryptedPayloads: BulkDecryptPayload

  constructor(
    client: Client,
    backend: CryptoBackend,
    encryptedPayloads: BulkDecryptPayload,
  ) {
    super()
    this.client = client
    this.backend = backend
    this.encryptedPayloads = encryptedPayloads
  }

  /**
   * Supply the identity claim the payloads were encrypted under.
   *
   * Returns a new operation rather than mutating this one. Audit metadata
   * already set is carried across; metadata added to *this* operation
   * afterwards is not.
   *
   * @param lockContext The claim used at encrypt time. It applies to the whole
   * batch, so payloads bound to different claims must be decrypted separately
   * — mixing them yields per-item errors for the ones that do not match.
   */
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

        const decryptedData = await this.backend.decryptBulkFallible(
          this.client,
          {
            ciphertexts: nonNullPayloads,
            unverifiedContext: metadata,
          },
        )

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

  /**
   * The operation's inputs, including its backend, so the lock-context variant
   * can run the same call with a context added. Internal to that handoff.
   */
  public getOperation(): {
    client: Client
    backend: CryptoBackend
    encryptedPayloads: BulkDecryptPayload
  } {
    return {
      client: this.client,
      backend: this.backend,
      encryptedPayloads: this.encryptedPayloads,
    }
  }
}

/**
 * {@link BulkDecryptOperation} supplying the identity claim its payloads were
 * encrypted under.
 *
 * Constructed by `BulkDecryptOperation.withLockContext()`, not directly.
 *
 * Note where the context goes: {@link CryptoBackend.decryptBulkFallible} takes
 * it on each payload item, not at the top level of the call, so it is threaded
 * through `createDecryptPayloads`. Everything else is the same path as the
 * unbound operation, including per-item error reporting.
 */
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
    const { client, backend, encryptedPayloads } = this.operation.getOperation()

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

        const decryptedData = await backend.decryptBulkFallible(client, {
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
