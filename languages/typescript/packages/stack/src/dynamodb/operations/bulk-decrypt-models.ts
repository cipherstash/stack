import { type Result, withResult } from '@byteslice/result'
import { reconstructDatePaths } from '@/eql/v3/date-reconstruction'
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
        // One set PER ITEM, not one for the batch: `details.placedAt` can be an
        // encrypted date column in one item and an ordinary plaintext string in
        // the next, and a shared set would convert the latter. See the
        // `aliasedDatePaths` note on `toItemWithEqlPayloads`.
        const aliasedDatePathsPerItem = this.items.map(() => new Set<string>())
        const itemsWithEqlPayloads = this.items.map((item, index) =>
          toItemWithEqlPayloads(
            item,
            this.table,
            readContext,
            aliasedDatePathsPerItem[index],
          ),
        )

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>[]>(
          client.bulkDecryptModels(itemsWithEqlPayloads, this.table),
          this.getAuditData(),
        )

        if (decryptResult.failure) {
          throwPreservingCode(decryptResult.failure)
        }

        // Rows come back in request order, so each item's aliased paths apply to
        // the row at the same index.
        return decryptResult.data.map((row, index) => {
          const paths = aliasedDatePathsPerItem[index]
          if (!paths || paths.size === 0) return row
          return reconstructDatePaths(row as Record<string, unknown>, [
            ...paths,
          ]) as Decrypted<T>
        })
      },
      (error) =>
        handleError(error, 'bulkDecryptModels', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
