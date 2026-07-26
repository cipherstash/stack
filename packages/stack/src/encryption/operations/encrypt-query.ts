import { type Result, withResult } from '@byteslice/result'
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { formatEncryptedResult } from '@/encryption/helpers'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type {
  Client,
  EncryptedQueryResult,
  EncryptQueryOptions,
  Plaintext,
} from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { resolveIndexType } from '../helpers/infer-index-type'
import {
  assertMatchNeedleQueryable,
  assertValueIndexCompatibility,
  validateNumericValue,
} from '../helpers/validation'
import { noClientError } from '../no-client-error'
import { EncryptionOperation } from './base-operation'

/**
 * Encrypts a single value into a **query term** — something to search *with*,
 * not something to store.
 *
 * Returned by `Encryption.encryptQuery()`. Both a builder and a promise: chain
 * `.audit()` / `.withLockContext()`, then `await` for a `Result` — see
 * {@link EncryptionOperation}.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry and on
 * `@cipherstash/stack/wasm-inline` (cipherstash/stack#798).
 *
 * ## What it validates before encrypting
 *
 * The term must be one the column can actually answer. `resolveIndexType`
 * picks the index from the column's declared type and the requested
 * `queryType`, then the value is checked against it — asking for a range term
 * on an equality-only column, or a match needle the column cannot search,
 * fails here rather than returning a term the database will silently never
 * match.
 *
 * `null` and `undefined` resolve to `{ data: null }` without an FFI call.
 */
export class EncryptQueryOperation extends EncryptionOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private backend: CryptoBackend,
    private plaintext: Plaintext | null | undefined,
    private opts: EncryptQueryOptions,
  ) {
    super()
  }

  /**
   * Derive the query term under an identity claim.
   *
   * Returns a new operation rather than mutating this one; audit metadata
   * already set is passed across.
   *
   * @param lockContext The claim the target values were encrypted under. A
   * term derived under a different claim will not match them — the context is
   * part of key derivation, so it changes the term itself.
   */
  public withLockContext(
    lockContext: LockContextInput,
  ): EncryptQueryOperationWithLockContext {
    return new EncryptQueryOperationWithLockContext(
      this.client,
      this.backend,
      this.plaintext,
      this.opts,
      lockContext,
      this.auditMetadata,
    )
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult, EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'encryptQuery',
      table: this.opts.table.tableName,
      column: this.opts.column.getName(),
      queryType: this.opts.queryType,
      lockContext: false,
    })

    if (this.plaintext === null || this.plaintext === undefined) {
      log.emit()
      return { data: null }
    }

    const plaintext: Plaintext = this.plaintext

    const validationError = validateNumericValue(plaintext)
    if (validationError?.failure) {
      log.emit()
      return { failure: validationError.failure }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const { metadata } = this.getAuditData()

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          plaintext,
          indexType,
          this.opts.column.getName(),
        )
        assertMatchNeedleQueryable(plaintext, indexType, this.opts.column)

        const encrypted = await this.backend.encryptQuery(this.client, {
          // `Plaintext` widens the FFI `JsPlaintext` with `Date` (serialized via
          // `toJSON` at the boundary); cast until the upstream input union is
          // corrected to include it.
          plaintext: plaintext as JsPlaintext,
          column: this.opts.column.getName(),
          table: this.opts.table.tableName,
          indexType,
          queryOp,
          unverifiedContext: metadata,
        })

        return formatEncryptedResult(encrypted, this.opts.returnType)
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

  public getOperation() {
    return { client: this.client, plaintext: this.plaintext, ...this.opts }
  }
}

/**
 * {@link EncryptQueryOperation} deriving its term under an identity claim.
 *
 * Constructed by `EncryptQueryOperation.withLockContext()`, not directly.
 * Unlike the encrypt/decrypt operations this takes its inputs by constructor
 * rather than reading them back from the source operation, but the executed
 * path — validation, index resolution, error mapping — is the same.
 */
export class EncryptQueryOperationWithLockContext extends EncryptionOperation<EncryptedQueryResult> {
  constructor(
    private client: Client,
    private backend: CryptoBackend,
    private plaintext: Plaintext | null | undefined,
    private opts: EncryptQueryOptions,
    private lockContext: LockContextInput,
    auditMetadata?: Record<string, unknown>,
  ) {
    super()
    this.auditMetadata = auditMetadata
  }

  public async execute(): Promise<
    Result<EncryptedQueryResult, EncryptionError>
  > {
    const log = createRequestLogger()
    log.set({
      op: 'encryptQuery',
      table: this.opts.table.tableName,
      column: this.opts.column.getName(),
      queryType: this.opts.queryType,
      lockContext: true,
    })

    if (this.plaintext === null || this.plaintext === undefined) {
      log.emit()
      return { data: null }
    }

    const plaintext: Plaintext = this.plaintext

    const validationError = validateNumericValue(plaintext)
    if (validationError?.failure) {
      log.emit()
      return { failure: validationError.failure }
    }

    const result = await withResult(
      async () => {
        if (!this.client) throw noClientError()

        const context = resolveLockContext(this.lockContext)

        const { metadata } = this.getAuditData()

        const { indexType, queryOp } = resolveIndexType(
          this.opts.column,
          this.opts.queryType,
          plaintext,
        )

        // Validate value/index compatibility
        assertValueIndexCompatibility(
          plaintext,
          indexType,
          this.opts.column.getName(),
        )
        assertMatchNeedleQueryable(plaintext, indexType, this.opts.column)

        const encrypted = await this.backend.encryptQuery(this.client, {
          // `Plaintext` widens the FFI `JsPlaintext` with `Date` (serialized via
          // `toJSON` at the boundary); cast until the upstream input union is
          // corrected to include it.
          plaintext: plaintext as JsPlaintext,
          column: this.opts.column.getName(),
          table: this.opts.table.tableName,
          indexType,
          queryOp,
          lockContext: context,
          unverifiedContext: metadata,
        })

        return formatEncryptedResult(encrypted, this.opts.returnType)
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
