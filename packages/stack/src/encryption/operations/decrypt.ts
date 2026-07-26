import { type Result, withResult } from '@byteslice/result'
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type { Client, Encrypted } from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../no-client-error'
import { EncryptionOperation } from './base-operation'

/**
 * Decrypts a single encrypted payload.
 *
 * Returned by the {@link EncryptionClient.decrypt | decrypt} method of the
 * {@link EncryptionClient}. Both a builder and a promise: chain `.audit()` /
 * `.withLockContext()`, then `await` for a `Result` — see
 * {@link EncryptionOperation}.
 *
 * Reads both EQL v2 and v3 payloads; the client only writes v3.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry and on
 * `@cipherstash/stack/wasm-inline` (cipherstash/stack#798).
 *
 * A `null` payload resolves to `null` without an FFI call, which is what makes
 * this safe to run over rows that predate encryption.
 */
export class DecryptOperation extends EncryptionOperation<JsPlaintext> {
  private client: Client
  private backend: CryptoBackend
  // Internally widened to allow null so the runtime guard below can
  // short-circuit on legacy / manually-NULLed rows. The public
  // `Encryption.decrypt()` signature still rejects null at the type
  // layer; this is defense in depth for direct construction.
  private encryptedData: Encrypted | null

  constructor(
    client: Client,
    backend: CryptoBackend,
    encryptedData: Encrypted | null,
  ) {
    super()
    this.client = client
    this.backend = backend
    this.encryptedData = encryptedData
  }

  /**
   * Supply the identity claim the payload was encrypted under.
   *
   * Returns a new operation rather than mutating this one. Audit metadata
   * already set is carried across; metadata added to *this* operation
   * afterwards is not.
   *
   * @param lockContext The claim used at encrypt time. It must match exactly —
   * a mismatch fails the decrypt, it does not fall back to an unbound key.
   */
  public withLockContext(
    lockContext: LockContextInput,
  ): DecryptOperationWithLockContext {
    return new DecryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<JsPlaintext, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'decrypt',
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.encryptedData === null) {
          // See encrypt.ts for the same defense-in-depth pattern.
          return null as unknown as JsPlaintext
        }

        const { metadata } = this.getAuditData()

        return await this.backend.decrypt(this.client, {
          ciphertext: this.encryptedData,
          unverifiedContext: metadata,
        })
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
    encryptedData: Encrypted | null
    auditData?: Record<string, unknown>
  } {
    return {
      client: this.client,
      backend: this.backend,
      encryptedData: this.encryptedData,
      auditData: this.getAuditData(),
    }
  }
}

/**
 * {@link DecryptOperation} supplying the identity claim the payload was
 * encrypted under.
 *
 * Constructed by `DecryptOperation.withLockContext()`, not directly. It reads
 * the source operation's inputs at execute time and adds `lockContext` to the
 * FFI call; everything else is the same path, deliberately.
 */
export class DecryptOperationWithLockContext extends EncryptionOperation<JsPlaintext> {
  private operation: DecryptOperation
  private lockContext: LockContextInput

  constructor(operation: DecryptOperation, lockContext: LockContextInput) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<JsPlaintext, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'decrypt',
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        const { client, backend, encryptedData } = this.operation.getOperation()

        if (!client) {
          throw noClientError()
        }

        if (encryptedData === null) {
          return null as unknown as JsPlaintext
        }

        const { metadata } = this.getAuditData()

        const lockContext = resolveLockContext(this.lockContext)

        return await backend.decrypt(client, {
          ciphertext: encryptedData,
          unverifiedContext: metadata,
          lockContext,
        })
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
