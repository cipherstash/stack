import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { EncryptedValue } from '@/types'
import { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import { DecryptModelOperation } from './operations/decrypt-model'
import { EncryptModelOperation } from './operations/encrypt-model'
import type {
  EncryptedDynamoDBConfig,
  EncryptedDynamoDBInstance,
} from './types'

/**
 * Create an encrypted DynamoDB helper bound to an `EncryptionClient`.
 *
 * Returns an object with `encryptModel`, `decryptModel`, `bulkEncryptModels`,
 * and `bulkDecryptModels` methods that transparently encrypt/decrypt DynamoDB
 * items according to the provided table schema.
 *
 * @param config - Configuration containing the `encryptionClient` and optional
 *   logging / error-handling callbacks.
 * @returns An {@link EncryptedDynamoDBInstance} with encrypt/decrypt operations.
 *
 * @example
 * ```typescript
 * import { Encryption } from "@cipherstash/stack"
 * import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"
 * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
 *
 * const users = encryptedTable("users", {
 *   email: encryptedColumn("email").equality(),
 * })
 *
 * const client = await Encryption({ schemas: [users] })
 * const dynamo = encryptedDynamoDB({ encryptionClient: client })
 *
 * const encrypted = await dynamo.encryptModel({ email: "a@b.com" }, users)
 * ```
 */
export function encryptedDynamoDB(
  config: EncryptedDynamoDBConfig,
): EncryptedDynamoDBInstance {
  const { encryptionClient, options } = config

  return {
    encryptModel<T extends Record<string, unknown>>(
      item: T,
      table: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new EncryptModelOperation<T>(
        encryptionClient,
        item,
        table,
        options,
      )
    },

    bulkEncryptModels<T extends Record<string, unknown>>(
      items: T[],
      table: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new BulkEncryptModelsOperation<T>(
        encryptionClient,
        items,
        table,
        options,
      )
    },

    decryptModel<T extends Record<string, unknown>>(
      item: Record<string, EncryptedValue | unknown>,
      table: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new DecryptModelOperation<T>(
        encryptionClient,
        item,
        table,
        options,
      )
    },

    bulkDecryptModels<T extends Record<string, unknown>>(
      items: Record<string, EncryptedValue | unknown>[],
      table: EncryptedTable<EncryptedTableColumn>,
    ) {
      return new BulkDecryptModelsOperation<T>(
        encryptionClient,
        items,
        table,
        options,
      )
    },
  }
}

export type {
  EncryptedDynamoDBConfig,
  EncryptedDynamoDBError,
  EncryptedDynamoDBInstance,
} from './types'

// Re-export the operation classes returned by the DynamoDB instance methods so
// they are part of the public API and appear in the generated reference.
export {
  BulkDecryptModelsOperation,
  BulkEncryptModelsOperation,
  DecryptModelOperation,
  EncryptModelOperation,
}
