import { type Result, withResult } from '@byteslice/result'
import { encrypt as ffiEncrypt } from '@cipherstash/protect-ffi'
import {
  failureDiagnostics,
  failureMessage,
} from '@/encryption/helpers/auth-failure'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { toJsPlaintext } from '@/encryption/helpers/js-plaintext'
import { assertValidNumericValue } from '@/encryption/helpers/validation'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { type LockContextInput, resolveLockContext } from '@/identity'
import type {
  BuildableColumn,
  BuildableTable,
  Client,
  Encrypted,
  EncryptOptions,
  PlaintextInput,
} from '@/types'
import { createRequestLogger } from '@/utils/logger'
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

/**
 * What an `encrypt` call resolves to for a plaintext of type `P`.
 *
 * `encrypt` short-circuits a `null` plaintext to a `null` result rather than
 * encrypting it, so the result admits `null` exactly when the argument's type
 * does. Only a `types.Json` column's plaintext (its document type includes
 * `null`) can be `null` through the typed client; every scalar column, and any
 * value the compiler knows is non-null, resolves to plain {@link Encrypted}.
 *
 * Written as an intersection rather than a conditional (`null extends P ? …`)
 * on purpose: `null & P` is `null` when `P` admits `null` and `never`
 * otherwise, which gives the same answer for every plaintext type, but stays
 * resolvable while `P` is still generic. A conditional on the generic `P` is
 * deferred, and expect-type's `toBeCallableWith` then reads the whole
 * signature as uncallable (`never`) — breaking callers' own type tests of
 * `client.encrypt`. The one divergence: an `any` plaintext yields `any`.
 */
export type EncryptResult<P> = Encrypted | (null & P)

/**
 * @typeParam R - the success `data` type: {@link Encrypted}, or
 *   `Encrypted | null` when the plaintext may be `null` (see
 *   {@link EncryptResult}). Defaults to `Encrypted`, so an unparameterised
 *   `EncryptOperation` names the non-null operation.
 */
export class EncryptOperation<
  R extends Encrypted | null = Encrypted,
> extends EncryptionOperation<R> {
  private client: Client
  // Widened to allow null so the runtime guard below can short-circuit.
  // `PlaintextInput` also admits the v3 `types.Json` document (see its
  // definition). The public `encrypt()` signature rejects null for every
  // scalar column; a `types.Json` column's document type does admit `null`,
  // and it short-circuits here like any other null.
  private plaintext: PlaintextInput | null
  private column: BuildableColumn
  private table: BuildableTable

  constructor(
    client: Client,
    plaintext: PlaintextInput | null,
    opts: EncryptOptions,
  ) {
    super()
    this.client = client
    this.plaintext = plaintext
    this.column = opts.column
    this.table = opts.table
  }

  public withLockContext(
    lockContext: LockContextInput,
  ): EncryptOperationWithLockContext<R> {
    return new EncryptOperationWithLockContext<R>(this, lockContext)
  }

  public async execute(): Promise<Result<R, EncryptionError>> {
    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: this.table.tableName,
      column: this.column.getName(),
      lockContext: false,
    })

    const result = await withResult(
      async (): Promise<Encrypted | null> => {
        if (!this.client) {
          throw noClientError()
        }

        if (this.plaintext === null) {
          // The public `encrypt()` signature rejects null for scalar columns,
          // but null can still arrive here via casts, dynamic field walking,
          // or a `types.Json` column (whose document type admits `null`).
          // Return null directly so the result matches DB NULL semantics
          // rather than encrypting JSON null into a SteVec. The typed client
          // reflects this in the result: when the argument's type admits
          // `null`, `R` is `Encrypted | null` (see `EncryptResult`), so a
          // caller must check `data` before dereferencing it.
          return null
        }

        assertValidNumericValue(this.plaintext)

        const { metadata } = this.getAuditData()

        return await ffiEncrypt(this.client, {
          plaintext: toJsPlaintext(this.plaintext),
          column: this.column.getName(),
          table: this.table.tableName,
          unverifiedContext: metadata,
        })
      },
      (error: unknown) => {
        log.set({ errorCode: getErrorCode(error) ?? 'unknown' })
        return {
          type: EncryptionErrorTypes.EncryptionError,
          message: failureMessage(error),
          ...failureDiagnostics(error, getErrorCode),
        }
      },
    )
    log.emit()
    // `R` is a statement about the caller's plaintext type that the runtime
    // value cannot carry: `null` comes back only for a `null` plaintext, and
    // `R` admits `null` whenever that argument's type does.
    return result as Result<R, EncryptionError>
  }

  public getOperation(): {
    client: Client
    plaintext: PlaintextInput | null
    column: BuildableColumn
    table: BuildableTable
  } {
    return {
      client: this.client,
      plaintext: this.plaintext,
      column: this.column,
      table: this.table,
    }
  }
}

export class EncryptOperationWithLockContext<
  R extends Encrypted | null = Encrypted,
> extends EncryptionOperation<R> {
  private operation: EncryptOperation<R>
  private lockContext: LockContextInput

  constructor(operation: EncryptOperation<R>, lockContext: LockContextInput) {
    super()
    this.operation = operation
    this.lockContext = lockContext
    const auditData = operation.getAuditData()
    if (auditData) {
      this.audit(auditData)
    }
  }

  public async execute(): Promise<Result<R, EncryptionError>> {
    const { client, plaintext, column, table } = this.operation.getOperation()

    const log = createRequestLogger()
    log.set({
      op: 'encrypt',
      table: table.tableName,
      column: column.getName(),
      lockContext: true,
    })

    const result = await withResult(
      async (): Promise<Encrypted | null> => {
        if (!client) {
          throw noClientError()
        }

        if (plaintext === null) {
          return null
        }

        assertValidNumericValue(plaintext)

        const { metadata } = this.getAuditData()
        const lockContext = resolveLockContext(this.lockContext)

        return await ffiEncrypt(client, {
          plaintext: toJsPlaintext(plaintext),
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
          message: failureMessage(error),
          ...failureDiagnostics(error, getErrorCode),
        }
      },
    )
    log.emit()
    // `R` is a statement about the caller's plaintext type that the runtime
    // value cannot carry: `null` comes back only for a `null` plaintext, and
    // `R` admits `null` whenever that argument's type does.
    return result as Result<R, EncryptionError>
  }
}
