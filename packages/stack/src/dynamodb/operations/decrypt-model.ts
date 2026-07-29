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

export class DecryptModelOperation<
  T extends Record<string, unknown>,
> extends DynamoDBOperation<Decrypted<T>> {
  private encryptionClient: DynamoDBEncryptionClient
  private item: Record<string, EncryptedValue | unknown>
  private table: AnyEncryptedTable
  private readOptions: DynamoDBReadOptions

  constructor(
    encryptionClient: DynamoDBEncryptionClient,
    item: Record<string, EncryptedValue | unknown>,
    table: AnyEncryptedTable,
    readOptions: DynamoDBReadOptions = {},
    options?: DynamoDBOperationOptions,
  ) {
    super(options)
    this.encryptionClient = encryptionClient
    this.item = item
    this.table = table
    this.readOptions = readOptions
  }

  public async execute(): Promise<
    Result<Decrypted<T>, EncryptedDynamoDBError>
  > {
    logger.debug('DynamoDB: decrypting model.')
    return await withResult(
      async () => {
        const storedEqlVersion = this.readOptions.storedEqlVersion ?? 3
        // A grouped v2 date column is matched by its bare leaf but lands at a
        // nested path the client's reconstructor does not know about — see the
        // `aliasedDatePaths` note on `toItemWithEqlPayloads`. Empty on a v3 read,
        // where the fallback never fires.
        const aliasedDatePaths = new Set<string>()
        const withEqlPayloads = toItemWithEqlPayloads(
          this.item,
          this.table,
          buildReadContext(this.table, storedEqlVersion),
          aliasedDatePaths,
        )

        const client = this.encryptionClient as CallableEncryptionClient
        const decryptResult = await resolveDecryptResult<Decrypted<T>>(
          // The table is always the registered v3 descriptor, even when the
          // stored envelope is v2. Passing it preserves Date reconstruction.
          client.decryptModel(withEqlPayloads, this.table),
          this.getAuditData(),
        )

        if (decryptResult.failure) {
          throwPreservingCode(decryptResult.failure)
        }

        if (aliasedDatePaths.size === 0) return decryptResult.data

        // `reconstructDatePaths` shallow-clones down each path, so the client's
        // own result object is never mutated.
        return reconstructDatePaths(
          decryptResult.data as Record<string, unknown>,
          [...aliasedDatePaths],
        ) as Decrypted<T>
      },
      (error) =>
        handleError(error, 'decryptModel', {
          logger: this.logger,
          errorHandler: this.errorHandler,
        }),
    )
  }
}
