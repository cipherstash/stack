import { type Result, withResult } from '@byteslice/result'
import type { Decrypted, EncryptedValue } from '@/types'
import { logger } from '@/utils/logger'
import {
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

export class DecryptModelOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<Decrypted<T>> {
  private encryptionClient: DynamoDBEncryptionClient
  private item: Record<string, EncryptedValue | unknown>
  private table: AnyEncryptedTable

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    item: Record<string, EncryptedValue | unknown>,
    table: AnyEncryptedTable,
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

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>>(
          // The typed client REQUIRES the table; the nominal one derives it
          // from the payloads and needs no second argument. Forwarding a v2
          // table unconditionally breaks this adapter's documented v2 read
          // path: a v3-configured typed client looks the table up in its own
          // reconstructor map, does not find it, and fails. Only a v3 table is
          // ever meaningful to that lookup, so only a v3 table is passed.
          isV3Table(this.table)
            ? client.decryptModel(withEqlPayloads, this.table)
            : client.decryptModel(withEqlPayloads),
          this.getAuditData(),
        )

        if (decryptResult.failure) {
          throwPreservingCode(decryptResult.failure)
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
