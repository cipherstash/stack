import { type Result, withResult } from '@byteslice/result'
import { encryptBulk, type JsPlaintext } from '@cipherstash/protect-ffi'
import { getErrorCode } from '@/encryption/helpers/error-code'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import {
  type Context,
  type LockContextInput,
  resolveLockContext,
} from '@/identity'
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
import { noClientError } from '../index'
import { EncryptionOperation } from './base-operation'

// Drops nulls so they don't reach protect-ffi (which would otherwise
// produce a SteVec wrapping the JSON null). The dropped positions are
// re-inserted as null in `mapEncryptedDataToResult`.
const createEncryptPayloads = (
  plaintexts: BulkEncryptPayload,
  column: BuildableColumn,
  table: BuildableTable,
  lockContext?: Context,
) => {
  return plaintexts
    .filter(({ plaintext }) => plaintext !== null)
    .map(({ id, plaintext }) => ({
      id,
      plaintext: plaintext as JsPlaintext,
      column: column.getName(),
      table: table.tableName,
      ...(lockContext && { lockContext }),
    }))
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

export class BulkEncryptOperation extends EncryptionOperation<BulkEncryptedData> {
  private client: Client
  private plaintexts: BulkEncryptPayload
  private column: BuildableColumn
  private table: BuildableTable

  constructor(
    client: Client,
    plaintexts: BulkEncryptPayload,
    opts: EncryptOptions,
  ) {
    super()
    this.client = client
    this.plaintexts = plaintexts
    this.column = opts.column
    this.table = opts.table
  }

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

        const encryptedData = await encryptBulk(this.client, {
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

  public getOperation(): {
    client: Client
    plaintexts: BulkEncryptPayload
    column: BuildableColumn
    table: BuildableTable
  } {
    return {
      client: this.client,
      plaintexts: this.plaintexts,
      column: this.column,
      table: this.table,
    }
  }
}

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
    const { client, plaintexts, column, table } = this.operation.getOperation()

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

        const encryptedData = await encryptBulk(client, {
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
