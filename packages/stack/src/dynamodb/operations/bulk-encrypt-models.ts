import { type Result, withResult } from '@byteslice/result'
import type { EncryptionClient } from '@/encryption'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import { logger } from '@/utils/logger'
import { deepClone, handleError, toEncryptedDynamoItem } from '../helpers'
import type { EncryptedDynamoDBError } from '../types'
import {
  DynamoDBOperation,
  type DynamoDBOperationOptions,
} from './base-operation'

export class BulkEncryptModelsOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<T[]> {
  private encryptionClient: EncryptionClient
  private items: T[]
  private table: EncryptedTable<EncryptedTableColumn>

  constructor(
    encryptionClient: EncryptionClient,
    items: T[],
    table: EncryptedTable<EncryptedTableColumn>,
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.items = items
    this.table = table
  }

  public async execute(): Promise<Result<T[], EncryptedDynamoDBError>> {
    logger.debug(`DynamoDB: bulk encrypting ${this.items.length} models.`)
    return await withResult(
      async () => {
        const encryptResult = await this.encryptionClient
          .bulkEncryptModels(
            this.items.map((item) => deepClone(item)),
            this.table,
          )
          .audit(this.getAuditData())

        if (encryptResult.failure) {
          // Create an Error object that preserves the FFI error code
          // This is necessary because withResult's ensureError wraps non-Error objects
          const error = new Error(encryptResult.failure.message) as Error & {
            code?: string
          }
          error.code = encryptResult.failure.code
          throw error
        }

        const data = encryptResult.data.map((item) => deepClone(item))
        const encryptedAttrs = Object.keys(this.table.build().columns)

        return data.map(
          (encrypted) => toEncryptedDynamoItem(encrypted, encryptedAttrs) as T,
        )
      },
      (error) =>
        handleError(error, 'bulkEncryptModels', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
