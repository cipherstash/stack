import { type Result, withResult } from '@byteslice/result'
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { toError } from '@/encryption/helpers/to-error'
import { assertValidNumericValue } from '@/encryption/helpers/validation'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type {
  BuildableColumn,
  BuildableTable,
  Client,
  Encrypted,
  EncryptOptions,
  Plaintext,
} from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../no-client-error'
import { EncryptionOperation } from './base-operation'

/**
 * Encrypts a single value for a single column.
 *
 * Returned by `Encryption.encrypt()`. Both a builder and a promise: chain
 * `.audit()` / `.withLockContext()`, then `await` for a `Result` — see
 * {@link EncryptionOperation}.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry (Node-API backend)
 * and on `@cipherstash/stack/wasm-inline` (WASM backend). The two entries
 * behave identically because they *are* the same code, not because two
 * implementations are kept in step — which is what they previously were, and
 * how they drifted (cipherstash/stack#798).
 *
 * A `null` plaintext resolves to `null` without an FFI call, so a NULL column
 * stays NULL rather than becoming an encrypted JSON null.
 */
export class EncryptOperation extends EncryptionOperation<Encrypted> {
  private client: Client
  private backend: CryptoBackend
  // Internally widened to allow null so the runtime guard below can
  // short-circuit. The public `Encryption.encrypt()` signature still
  // rejects null at the type layer; this is defense in depth for callers
  // that reach this class through casts or dynamic field walking.
  private plaintext: Plaintext | null
  private column: BuildableColumn
  private table: BuildableTable

  constructor(
    client: Client,
    backend: CryptoBackend,
    plaintext: Plaintext | null,
    opts: EncryptOptions,
  ) {
    super()
    this.client = client
    this.backend = backend
    this.plaintext = plaintext
    this.column = opts.column
    this.table = opts.table
  }

  /**
   * Bind the data key to an identity claim.
   *
   * Returns a new operation rather than mutating this one. Audit metadata
   * already set is carried across; metadata added to *this* operation
   * afterwards is not.
   *
   * @param lockContext The claim to bind to — a `{ identityClaim }` object, or
   * a `LockContext`. The same claim is required to decrypt.
   */
  public withLockContext(
    lockContext: LockContextInput,
  ): EncryptOperationWithLockContext {
    return new EncryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<Encrypted, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: this.table.tableName,
      column: this.column.getName(),
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.plaintext === null) {
          // Defense in depth: the public `Encryption.encrypt()` signature
          // rejects null, but null can still arrive here via casts or
          // dynamic field walking. Return null directly so the result
          // matches DB NULL semantics rather than encrypting JSON null
          // into a SteVec. The cast acknowledges the type-narrow
          // contract at the public boundary.
          return null as unknown as Encrypted
        }

        assertValidNumericValue(this.plaintext)

        const { metadata } = this.getAuditData()

        return await this.backend.encrypt(this.client, {
          // `Plaintext` widens the FFI `JsPlaintext` with `Date` (serialized via
          // `toJSON` at the boundary); cast until the upstream `JsPlaintext` input
          // union is corrected to include it.
          plaintext: this.plaintext as JsPlaintext,
          column: this.column.getName(),
          table: this.table.tableName,
          unverifiedContext: metadata,
        })
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.EncryptionError,
          message: (error as Error).message,
          code: getErrorCode(error),
        }
      },
      { onException: toError },
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
    plaintext: Plaintext | null
    column: BuildableColumn
    table: BuildableTable
  } {
    return {
      client: this.client,
      backend: this.backend,
      plaintext: this.plaintext,
      column: this.column,
      table: this.table,
    }
  }
}

/**
 * {@link EncryptOperation} with the data key bound to an identity claim.
 *
 * Constructed by `EncryptOperation.withLockContext()`, not directly. It reads
 * the source operation's inputs at execute time and adds `lockContext` to the
 * FFI call — the null short-circuit, validation, and error mapping are the
 * same, deliberately.
 *
 * The resulting value can ONLY be decrypted by supplying the same claim: the
 * context changes key derivation, so it is not a filter that can be skipped on
 * the way back out.
 */
export class EncryptOperationWithLockContext extends EncryptionOperation<Encrypted> {
  private operation: EncryptOperation
  private lockContext: LockContextInput

  constructor(operation: EncryptOperation, lockContext: LockContextInput) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<Encrypted, EncryptionError>> {
    const { client, backend, plaintext, column, table } =
      this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: table.tableName,
      column: column.getName(),
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }

        if (plaintext === null) {
          return null as unknown as Encrypted
        }

        assertValidNumericValue(plaintext)

        const { metadata } = this.getAuditData()
        const lockContext = resolveLockContext(this.lockContext)

        return await backend.encrypt(client, {
          plaintext: plaintext as JsPlaintext,
          column: column.getName(),
          table: table.tableName,
          lockContext,
          unverifiedContext: metadata,
        })
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.EncryptionError,
          message: (error as Error).message,
          code: getErrorCode(error),
        }
      },
      { onException: toError },
    )
    log.emit()
    return result
  }
}
