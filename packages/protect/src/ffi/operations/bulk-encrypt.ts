import { type Result, withResult } from '@byteslice/result'
import { encryptBulk, type JsPlaintext } from '@cipherstash/protect-ffi'
import type {
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
  ProtectValue,
} from '@cipherstash/schema'
import { logger } from '../../../../utils/logger'
import { type ProtectError, ProtectErrorTypes } from '../..'
import type { Context, LockContext } from '../../identify'
import type {
  BulkEncryptedData,
  BulkEncryptPayload,
  Client,
  Encrypted,
  EncryptOptions,
} from '../../types'
import { getErrorCode } from '../helpers/error-code'
import { noClientError } from '../index'
import { ProtectOperation } from './base-operation'

// Helper functions for better composability
const createEncryptPayloads = (
  plaintexts: BulkEncryptPayload,
  column: ProtectColumn | ProtectValue,
  table: ProtectTable<ProtectTableColumn>,
  lockContext?: Context,
) => {
  return plaintexts
    .map((item, index) => ({ ...item, originalIndex: index }))
    .filter(({ plaintext }) => plaintext !== null)
    .map(({ id, plaintext, originalIndex }) => ({
      id,
      plaintext: plaintext as JsPlaintext,
      column: column.getName(),
      table: table.tableName,
      originalIndex,
      ...(lockContext && { lockContext }),
    }))
}

const createNullResult = (
  plaintexts: BulkEncryptPayload,
): BulkEncryptedData => {
  return plaintexts.map(({ id }) => ({ id, data: null }))
}

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
      result[i] = {
        id: plaintexts[i].id,
        data: encryptedData[encryptedIndex],
      }
      encryptedIndex++
    }
  }

  return result
}

export class BulkEncryptOperation extends ProtectOperation<BulkEncryptedData> {
  private client: Client
  private plaintexts: BulkEncryptPayload
  private column: ProtectColumn | ProtectValue
  private table: ProtectTable<ProtectTableColumn>

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
    lockContext: LockContext,
  ): BulkEncryptOperationWithLockContext {
    return new BulkEncryptOperationWithLockContext(this, lockContext)
  }

  public async execute(): Promise<Result<BulkEncryptedData, ProtectError>> {
    logger.debug('Bulk encrypting data WITHOUT a lock context', {
      column: this.column.getName(),
      table: this.table.tableName,
    })

    return await withResult(
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
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }

  public getOperation(): {
    client: Client
    plaintexts: BulkEncryptPayload
    column: ProtectColumn | ProtectValue
    table: ProtectTable<ProtectTableColumn>
  } {
    return {
      client: this.client,
      plaintexts: this.plaintexts,
      column: this.column,
      table: this.table,
    }
  }
}

export class BulkEncryptOperationWithLockContext extends ProtectOperation<BulkEncryptedData> {
  private operation: BulkEncryptOperation
  private lockContext: LockContext

  constructor(operation: BulkEncryptOperation, lockContext: LockContext) {
    super()
    this.operation = operation
    this.lockContext = lockContext
  }

  public async execute(): Promise<Result<BulkEncryptedData, ProtectError>> {
    return await withResult(
      async () => {
        const { client, plaintexts, column, table } =
          this.operation.getOperation()

        logger.debug('Bulk encrypting data WITH a lock context', {
          column: column.getName(),
          table: table.tableName,
        })

        if (!client) {
          throw noClientError()
        }
        if (!plaintexts || plaintexts.length === 0) {
          return []
        }

        const context = await this.lockContext.getLockContext()
        if (context.failure) {
          throw new Error(`[protect]: ${context.failure.message}`)
        }

        const nonNullPayloads = createEncryptPayloads(
          plaintexts,
          column,
          table,
          context.data.context,
        )

        if (nonNullPayloads.length === 0) {
          return createNullResult(plaintexts)
        }

        const { metadata } = this.getAuditData()

        const encryptedData = await encryptBulk(client, {
          plaintexts: nonNullPayloads,
          serviceToken: context.data.ctsToken,
          unverifiedContext: metadata,
        })

        return mapEncryptedDataToResult(plaintexts, encryptedData)
      },
      (error: unknown) => ({
        type: ProtectErrorTypes.EncryptionError,
        message: (error as Error).message,
        code: getErrorCode(error),
      }),
    )
  }
}
