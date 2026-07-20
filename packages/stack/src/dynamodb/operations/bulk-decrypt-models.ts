import { type Result, withResult } from '@byteslice/result'
import type { Decrypted, EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import {
  handleError,
  resolveDecryptResult,
  throwPreservingCode,
  toItemWithEqlPayloads,
} from '../helpers'
import type {
  AnyEncryptedTable,
  CallableEncryptionClient,
  DynamoDBEncryptionClient,
  EncryptedDynamoDBError,
} from '../types'
import {
  DynamoDBOperation,
  type DynamoDBOperationOptions,
} from './base-operation'

export class BulkDecryptModelsOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<Decrypted<T>[]> {
  private encryptionClient: DynamoDBEncryptionClient
  private items: Record<string, EncryptedValue | unknown>[]
  private table: AnyEncryptedTable

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    items: Record<string, EncryptedValue | unknown>[],
    table: AnyEncryptedTable,
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.items = items
    this.table = table
  }

  public async execute(): Promise<
    Result<Decrypted<T>[], EncryptedDynamoDBError>
  > {
    logger.debug(`DynamoDB: bulk decrypting ${this.items.length} models.`)
    return await withResult(
      async () => {
        const itemsWithEqlPayloads = this.items.map((item) =>
          toItemWithEqlPayloads(item, this.table),
        )

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>[]>(
          // The second argument is required by the typed client and ignored by
          // the nominal one, which derives the table from the payloads.
          client.bulkDecryptModels(itemsWithEqlPayloads, this.table),
          this.getAuditData(),
        )

        if (decryptResult.failure) {
          throwPreservingCode(decryptResult.failure)
        }

        return decryptResult.data
      },
      (error) =>
        handleError(error, 'bulkDecryptModels', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
