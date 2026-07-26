import { type Result, withResult } from '@byteslice/result'
import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { CryptoBackend } from '@/encryption/backend'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { assertValidNumericValue } from '@/encryption/helpers/validation'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { Context } from '@/identity'
import {
  type LockContextInput,
  resolveLockContext,
} from '@/identity/resolve-lock-context'
import type {
  BuildableColumn,
  BuildableTable,
  BulkEncryptedData,
  BulkEncryptPayload,
  Client,
  Encrypted,
  EncryptOptions,
} from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../no-client-error'
import { EncryptionOperation } from './base-operation'

// Drops nulls so they don't reach protect-ffi (which would otherwise
// produce a SteVec wrapping the JSON null). The dropped positions are
// re-inserted as null in `mapEncryptedDataToResult`.
//
// Each surviving plaintext is validated exactly as `EncryptOperation` validates
// its single operand: NaN / ±Infinity / out-of-int64 `bigint` are rejected
// client-side, because protect-ffi's behaviour on such a value is unobservable.
// Callers that batch instead of looping (the v3 Drizzle `inArray`, for one)
// must not lose that guard by choosing the bulk path.
const createEncryptPayloads = (
  plaintexts: BulkEncryptPayload,
  column: BuildableColumn,
  table: BuildableTable,
  lockContext?: Context,
) => {
  return plaintexts
    .filter(({ plaintext }) => plaintext !== null)
    .map(({ id, plaintext }) => {
      assertValidNumericValue(plaintext)
      return {
        id,
        plaintext: plaintext as JsPlaintext,
        column: column.getName(),
        table: table.tableName,
        ...(lockContext && { lockContext }),
      }
    })
}

const createNullResult = (plaintexts: BulkEncryptPayload): BulkEncryptedData =>
  plaintexts.map(({ id }) => ({ id, data: null }))

const mapEncryptedDataToResult = (
  plaintexts: BulkEncryptPayload,
  encryptedData: Encrypted[],
): BulkEncryptedData => {
  const result: BulkEncryptedData = new Array(plaintexts.length)
  let encryptedIndex = 0
  for (let i = 0; i < plaintexts.length; i++) {
    if (plaintexts[i].plaintext === null) {
      result[i] = { id: plaintexts[i].id, data: null }
    } else {
      result[i] = { id: plaintexts[i].id, data: encryptedData[encryptedIndex] }
      encryptedIndex++
    }
  }
  return result
}

/**
 * Encrypts many values in one ZeroKMS round trip — the fast path, and the
 * reason to prefer this over looping `encrypt()`.
 *
 * Returned by `Encryption.bulkEncrypt()`. Both a builder and a promise: chain
 * `.audit()` / `.withLockContext()`, then `await` for a `Result` — see
 * {@link EncryptionOperation}.
 *
 * ## One implementation, both entries
 *
 * The FFI arrives as an injected {@link CryptoBackend} rather than a module
 * import, so this class runs unchanged on the native entry and on
 * `@cipherstash/stack/wasm-inline` (cipherstash/stack#798).
 *
 * ## Nulls and position
 *
 * Nulls never reach the FFI — they are filtered out before the call and
 * re-inserted at their original indices afterwards. So the result is always
 * the same length and order as the input, and a NULL column stays NULL rather
 * than becoming an encrypted JSON null. That re-insertion depends on
 * {@link CryptoBackend.encryptBulk} returning results in the order it was
 * given them.
 *
 * All-or-nothing: bulk encrypt has no per-item error channel, so one invalid
 * value fails the batch. (Bulk *decrypt* does report per item — see
 * `BulkDecryptOperation`.)
 */
export class BulkEncryptOperation extends EncryptionOperation<BulkEncryptedData> {
  private client: Client
  private backend: CryptoBackend
  private plaintexts: BulkEncryptPayload
  private column: BuildableColumn
  private table: BuildableTable

  constructor(
    client: Client,
    backend: CryptoBackend,
    plaintexts: BulkEncryptPayload,
    opts: EncryptOptions,
  ) {
    super()
    this.client = client
    this.backend = backend
    this.plaintexts = plaintexts
    this.column = opts.column
    this.table = opts.table
  }

  /**
   * Bind every value in the batch to an identity claim.
   *
   * Returns a new operation rather than mutating this one. Audit metadata
   * already set is carried across; metadata added to *this* operation
   * afterwards is not.
   *
   * @param lockContext The claim to bind to. It applies to the whole batch —
   * per-value contexts would require separate calls.
   */
  public withLockContext(
    lockContext: LockContextInput,
  ): BulkEncryptOperationWithLockContext {
    return new BulkEncryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<BulkEncryptedData, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'bulkEncrypt',
      table: this.table.tableName,
      column: this.column.getName(),
      count: this.plaintexts?.length ?? 0,
      lockContext: false,
    })

    const result = await withResult(
      async () => {
        if (!this.client) {
          throw noClientError()
        }
        if (!this.plaintexts || this.plaintexts.length === 0) {
          return []
        }

        const nonNullPayloads = createEncryptPayloads(
          this.plaintexts,
          this.column,
          this.table,
        )

        if (nonNullPayloads.length === 0) {
          return createNullResult(this.plaintexts)
        }

        const { metadata } = this.getAuditData()

        const encryptedData = await this.backend.encryptBulk(this.client, {
          plaintexts: nonNullPayloads,
          unverifiedContext: metadata,
        })

        return mapEncryptedDataToResult(this.plaintexts, encryptedData)
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

  /**
   * The operation's inputs, including its backend, so the lock-context variant
   * can run the same call with a context added. Internal to that handoff.
   */
  public getOperation(): {
    client: Client
    backend: CryptoBackend
    plaintexts: BulkEncryptPayload
    column: BuildableColumn
    table: BuildableTable
  } {
    return {
      client: this.client,
      backend: this.backend,
      plaintexts: this.plaintexts,
      column: this.column,
      table: this.table,
    }
  }
}

/**
 * {@link BulkEncryptOperation} with every data key bound to an identity claim.
 *
 * Constructed by `BulkEncryptOperation.withLockContext()`, not directly.
 *
 * Note where the context goes: {@link CryptoBackend.encryptBulk} takes it on
 * each payload item, not at the top level of the call, so it is threaded
 * through `createEncryptPayloads` rather than passed alongside
 * `unverifiedContext`. Everything else is the same path as the unbound
 * operation.
 */
export class BulkEncryptOperationWithLockContext extends EncryptionOperation<BulkEncryptedData> {
  private operation: BulkEncryptOperation
  private lockContext: LockContextInput

  constructor(operation: BulkEncryptOperation, lockContext: LockContextInput) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<BulkEncryptedData, EncryptionError>> {
    const { client, backend, plaintexts, column, table } =
      this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'bulkEncrypt',
      table: table.tableName,
      column: column.getName(),
      count: plaintexts?.length ?? 0,
      lockContext: true,
    })

    const result = await withResult(
      async () => {
        if (!client) {
          throw noClientError()
        }
        if (!plaintexts || plaintexts.length === 0) {
          return []
        }

        const lockContext = resolveLockContext(this.lockContext)

        const nonNullPayloads = createEncryptPayloads(
          plaintexts,
          column,
          table,
          lockContext,
        )

        if (nonNullPayloads.length === 0) {
          return createNullResult(plaintexts)
        }

        const { metadata } = this.getAuditData()

        const encryptedData = await backend.encryptBulk(client, {
          plaintexts: nonNullPayloads,
          unverifiedContext: metadata,
        })

        return mapEncryptedDataToResult(plaintexts, encryptedData)
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
