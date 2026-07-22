import { type Result, withResult } from '@byteslice/result'
import { resolveEncryptColumnMap } from '@/encryption/helpers/model-helpers'
import { logger } from '@/utils/logger'
import {
  deepClone,
  handleError,
  isV3Table,
  throwPreservingCode,
  toEncryptedDynamoItem,
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

export class BulkEncryptModelsOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<T[]> {
  private encryptionClient: DynamoDBEncryptionClient
  private items: T[]
  private table: AnyEncryptedTable

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    items: T[],
    table: AnyEncryptedTable,
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
        const client = this.encryptionClient as CallableEncryptionClient
        const encryptResult = await client
          .bulkEncryptModels(
            this.items.map((item) => deepClone(item)),
            this.table,
          )
          .audit(this.getAuditData())

        if (encryptResult.failure) {
          throwPreservingCode(encryptResult.failure)
        }

        const data = encryptResult.data.map((item) => deepClone(item))
        // Property names, NOT `build().columns` keys: for v3 those are the DB
        // column names, which differ whenever a column is declared
        // `emailAddress: types.TextEq('email_address')`. The encrypted model
        // coming back from the client is keyed by property name, so matching on
        // config keys silently missed the attribute entirely.
        const { columnPaths: encryptedAttrs } = resolveEncryptColumnMap(
          this.table,
        )

        const isV3 = isV3Table(this.table)
        return data.map(
          (encrypted) =>
            toEncryptedDynamoItem(encrypted, encryptedAttrs, isV3) as T,
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
