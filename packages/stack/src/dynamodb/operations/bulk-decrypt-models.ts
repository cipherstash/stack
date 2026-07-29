import { type Result, withResult } from '@byteslice/result'
import type { Decrypted, EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import {
  buildReadContext,
  handleError,
  resolveDecryptResult,
  throwPreservingCode,
  toItemWithEqlPayloads,
} from '../helpers'
import type {
  AnyEncryptedTable,
  CallableEncryptionClient,
  DynamoDBEncryptionClient,
  DynamoDBReadOptions,
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
  private readOptions: DynamoDBReadOptions

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    items: Record<string, EncryptedValue | unknown>[],
    table: AnyEncryptedTable,
    readOptions: DynamoDBReadOptions = {},
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.items = items
    this.table = table
    this.readOptions = readOptions
  }

  public async execute(): Promise<
    Result<Decrypted<T>[], EncryptedDynamoDBError>
  > {
    logger.debug(`DynamoDB: bulk decrypting ${this.items.length} models.`)
    return await withResult(
      async () => {
        // Resolve the table's read context once, not once per item — `build()`
        // and the column map are row-invariant.
        const storedEqlVersion = this.readOptions.storedEqlVersion ?? 3
        const readContext = buildReadContext(this.table, storedEqlVersion)
        const itemsWithEqlPayloads = this.items.map((item) =>
          toItemWithEqlPayloads(item, this.table, readContext),
        )

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>[]>(
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
