import { type Result, withResult } from '@byteslice/result'
import type { EncryptionClient } from '@/encryption'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { Decrypted, EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import { handleError, toItemWithEqlPayloads } from '../helpers'
import type { EncryptedDynamoDBError } from '../types'
import {
  DynamoDBOperation,
  type DynamoDBOperationOptions,
} from './base-operation'

export class DecryptModelOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<Decrypted<T>> {
  private encryptionClient: EncryptionClient
  private item: Record<string, EncryptedValue | unknown>
  private table: EncryptedTable<EncryptedTableColumn>

  constructor(
    encryptionClient: EncryptionClient,
    item: Record<string, EncryptedValue | unknown>,
    table: EncryptedTable<EncryptedTableColumn>,
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.item = item
    this.table = table
  }

  public async execute(): Promise<
    Result<Decrypted<T>, EncryptedDynamoDBError>
  > {
    logger.debug('DynamoDB: decrypting model.')
    return await withResult(
      async () => {
        const withEqlPayloads = toItemWithEqlPayloads(this.item, this.table)

        const decryptResult = await this.encryptionClient
          .decryptModel<T>(withEqlPayloads as T)
          .audit(this.getAuditData())

        if (decryptResult.failure) {
          // Create an Error object that preserves the FFI error code
          // This is necessary because withResult's ensureError wraps non-Error objects
          const error = new Error(decryptResult.failure.message) as Error & {
            code?: string
          }
          error.code = decryptResult.failure.code
          throw error
        }

        return decryptResult.data
      },
      (error) =>
        handleError(error, 'decryptModel', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
