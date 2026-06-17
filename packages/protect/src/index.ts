import type { ProtectTable, ProtectTableColumn } from '@cipherstash/schema'
import { buildEncryptConfig } from '@cipherstash/schema'
import { ProtectClient } from './ffi'
import type { KeysetIdentifier } from './types'

// Re-export FFI error types for programmatic error handling
export {
  ProtectError as FfiProtectError,
  type ProtectErrorCode,
} from '@cipherstash/protect-ffi'

export const ProtectErrorTypes = {
  ClientInitError: 'ClientInitError',
  EncryptionError: 'EncryptionError',
  DecryptionError: 'DecryptionError',
  LockContextError: 'LockContextError',
  CtsTokenError: 'CtsTokenError',
}

export interface ProtectError {
  type: (typeof ProtectErrorTypes)[keyof typeof ProtectErrorTypes]
  message: string
  code?: import('@cipherstash/protect-ffi').ProtectErrorCode
}

type AtLeastOneCsTable<T> = [T, ...T[]]

export type ProtectClientConfig = {
  schemas: AtLeastOneCsTable<ProtectTable<ProtectTableColumn>>

  /**
   * The CipherStash workspace CRN (Cloud Resource Name).
   * Format: `crn:<region>.aws:<workspace-id>`.
   * Can also be set via the `CS_WORKSPACE_CRN` environment variable.
   */
  workspaceCrn?: string

  /**
   * The API access key used for authenticating with the CipherStash API.
   * Can also be set via the `CS_CLIENT_ACCESS_KEY` environment variable.
   * Obtain this from the CipherStash dashboard after creating a workspace.
   */
  accessKey?: string

  /**
   * The client identifier used to authenticate with CipherStash services.
   * Can also be set via the `CS_CLIENT_ID` environment variable.
   * Generated during workspace onboarding in the CipherStash dashboard.
   */
  clientId?: string

  /**
   * The client key material used in combination with ZeroKMS for encryption operations.
   * Can also be set via the `CS_CLIENT_KEY` environment variable.
   * Generated during workspace onboarding in the CipherStash dashboard.
   */
  clientKey?: string

  /**
   * An optional keyset identifier for multi-tenant encryption.
   * Each keyset provides cryptographic isolation, giving each tenant its own keyspace.
   * Specify by name (`{ name: "tenant-a" }`) or UUID (`{ id: "..." }`).
   * Keysets are created and managed in the CipherStash dashboard.
   */
  keyset?: KeysetIdentifier
}

function isValidUuid(uuid: string): boolean {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
  return uuidRegex.test(uuid)
}

/* Initialize a Protect client with the provided configuration.

  @param config - The configuration object for initializing the Protect client.

  @see {@link ProtectClientConfig} for details on the configuration options.

  @returns A Promise that resolves to an instance of ProtectClient.

  @throws Will throw an error if no schemas are provided or if the keyset ID is not a valid UUID.
*/
export const protect = async (
  config: ProtectClientConfig,
): Promise<ProtectClient> => {
  const { schemas } = config

  if (!schemas.length) {
    throw new Error(
      '[protect]: At least one csTable must be provided to initialize the protect client',
    )
  }

  if (
    config.keyset &&
    'id' in config.keyset &&
    !isValidUuid(config.keyset.id)
  ) {
    throw new Error(
      '[protect]: Invalid UUID provided for keyset id. Must be a valid UUID.',
    )
  }

  const clientConfig = {
    workspaceCrn: config.workspaceCrn,
    accessKey: config.accessKey,
    clientId: config.clientId,
    clientKey: config.clientKey,
    keyset: config.keyset,
  }

  const client = new ProtectClient()
  const encryptConfig = buildEncryptConfig(...schemas)

  const result = await client.init({
    encryptConfig,
    ...clientConfig,
  })

  if (result.failure) {
    throw new Error(`[protect]: ${result.failure.message}`)
  }

  return result.data
}

export type { Result } from '@byteslice/result'
export type {
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
  ProtectValue,
} from '@cipherstash/schema'
export { csColumn, csTable, csValue } from '@cipherstash/schema'
export type { ProtectClient } from './ffi'
// Helpers
export {
  inferIndexType,
  validateIndexType,
} from './ffi/helpers/infer-index-type'
export type { ProtectOperation } from './ffi/operations/base-operation'
export {
  BatchEncryptQueryOperation,
  BatchEncryptQueryOperationWithLockContext,
} from './ffi/operations/batch-encrypt-query'
export type { BulkDecryptOperation } from './ffi/operations/bulk-decrypt'
export type { BulkDecryptModelsOperation } from './ffi/operations/bulk-decrypt-models'
export type { BulkEncryptOperation } from './ffi/operations/bulk-encrypt'
export type { BulkEncryptModelsOperation } from './ffi/operations/bulk-encrypt-models'
export type { DecryptOperation } from './ffi/operations/decrypt'
export type { DecryptModelOperation } from './ffi/operations/decrypt-model'
export type { EncryptOperation } from './ffi/operations/encrypt'
export type { EncryptModelOperation } from './ffi/operations/encrypt-model'
// Operations
export {
  EncryptQueryOperation,
  EncryptQueryOperationWithLockContext,
} from './ffi/operations/encrypt-query'
export * from './helpers'
// LockContext related type exports
export type {
  Context,
  CtsRegions,
  CtsToken,
  GetLockContextResponse,
  IdentifyOptions,
  LockContextOptions,
} from './identify'
// LockContext class export (value export for instantiation)
export { LockContext } from './identify'
// Types
export type {
  EncryptQueryOptions,
  FfiIndexTypeName,
  QueryTypeName,
  ScalarQueryTerm,
} from './types'
export * from './types'
export { queryTypes, queryTypeToFfi } from './types'
