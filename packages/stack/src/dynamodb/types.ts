import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import type { EncryptionClient } from '@/encryption'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { EncryptedValue } from '@/types'
import type { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import type { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import type { DecryptModelOperation } from './operations/decrypt-model'
import type { EncryptModelOperation } from './operations/encrypt-model'

export interface EncryptedDynamoDBConfig {
  encryptionClient: EncryptionClient
  options?: {
    logger?: {
      error: (message: string, error: Error) => void
    }
    errorHandler?: (error: EncryptedDynamoDBError) => void
  }
}

export interface EncryptedDynamoDBError extends Error {
  code: ProtectErrorCode | 'DYNAMODB_ENCRYPTION_ERROR'
  details?: Record<string, unknown>
}

export interface EncryptedDynamoDBInstance {
  encryptModel<T extends Record<string, unknown>>(
    item: T,
    table: EncryptedTable<EncryptedTableColumn>,
  ): EncryptModelOperation<T>

  bulkEncryptModels<T extends Record<string, unknown>>(
    items: T[],
    table: EncryptedTable<EncryptedTableColumn>,
  ): BulkEncryptModelsOperation<T>

  decryptModel<T extends Record<string, unknown>>(
    item: Record<string, EncryptedValue | unknown>,
    table: EncryptedTable<EncryptedTableColumn>,
  ): DecryptModelOperation<T>

  bulkDecryptModels<T extends Record<string, unknown>>(
    items: Record<string, EncryptedValue | unknown>[],
    table: EncryptedTable<EncryptedTableColumn>,
  ): BulkDecryptModelsOperation<T>
}
