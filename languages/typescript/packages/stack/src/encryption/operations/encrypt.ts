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

export class EncryptOperation extends EncryptionOperation<Encrypted> {
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
          // The public `encrypt()` signature rejects null for scalar columns,
          // but null can still arrive here via casts, dynamic field walking,
          // or a `types.Json` column (whose document type admits `null`).
          // Return null directly so the result
          // matches DB NULL semantics rather than encrypting JSON null
          // into a SteVec. The cast does NOT reflect a narrow contract:
          // for a `types.Json` column the public type admits `null`, yet the
          // result is still typed `Encrypted` while carrying `null` at
          // runtime. That type mismatch is a known gap, tracked as a
          // follow-up.
          return null as unknown as Encrypted
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
    return result
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
    const { client, plaintext, column, table } = this.operation.getOperation()

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
    return result
  }
}
