import { type Result, withResult } from '@byteslice/result'
import { logger } from '@/utils/logger'
import {
  deepClone,
  handleError,
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

export class EncryptModelOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<T> {
  private encryptionClient: DynamoDBEncryptionClient
  private item: T
  private table: AnyEncryptedTable

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    item: T,
    table: AnyEncryptedTable,
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.item = item
    this.table = table
  }

  public async execute(): Promise<Result<T, EncryptedDynamoDBError>> {
    logger.debug('DynamoDB: encrypting model.')
    return await withResult(
      async () => {
        const client = this.encryptionClient as CallableEncryptionClient
        const encryptResult = await client
          .encryptModel(deepClone(this.item), this.table)
          .audit(this.getAuditData())

        if (encryptResult.failure) {
          throwPreservingCode(encryptResult.failure)
        }

        const data = deepClone(encryptResult.data)
        const encryptedAttrs = Object.keys(this.table.build().columns)

        return toEncryptedDynamoItem(data, encryptedAttrs) as T
      },
      (error) =>
        handleError(error, 'encryptModel', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
