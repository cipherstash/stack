import { type Result, withResult } from '@byteslice/result'
import type { Decrypted, EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import {
  buildReadContext,
  handleError,
  isV3Table,
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
        // Resolve the table's read context once, not once per item — `build()`
        // and the column map are row-invariant.
        const readContext = buildReadContext(this.table)
        const itemsWithEqlPayloads = this.items.map((item) =>
          toItemWithEqlPayloads(item, this.table, readContext),
        )

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>[]>(
          // Conditional for the same reason as `decryptModel` — see the note
          // there. A v2 table forwarded to a v3-configured typed client is
          // rejected by its reconstructor lookup, breaking the v2 read path
          // this adapter documents as supported.
          isV3Table(this.table)
            ? client.bulkDecryptModels(itemsWithEqlPayloads, this.table)
            : client.bulkDecryptModels(itemsWithEqlPayloads),
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
