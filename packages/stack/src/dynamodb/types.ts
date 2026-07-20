import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import type { EncryptionClient } from '@/encryption'
import type { AnyV3Table } from '@/eql/v3'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { EncryptedValue } from '@/types'
import type { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import type { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import type { DecryptModelOperation } from './operations/decrypt-model'
import type { EncryptModelOperation } from './operations/encrypt-model'

/**
 * A table this adapter accepts: either an EQL v2 table (`encryptedTable` +
 * `encryptedColumn`/`encryptedField` from `@cipherstash/stack/schema`) or an
 * EQL v3 one (`encryptedTable` + `types.*` from `@cipherstash/stack/eql/v3`).
 *
 * Both are supported deliberately. DynamoDB shares none of the v2 Postgres
 * machinery — there is no EQL extension to install and no migration to run —
 * so accepting v3 is purely additive and no existing caller has to change.
 */
export type AnyEncryptedTable =
  | EncryptedTable<EncryptedTableColumn>
  | AnyV3Table

/**
 * The client capability this adapter consumes, declared structurally so it is
 * satisfied by the nominal {@link EncryptionClient} AND by the
 * `TypedEncryptionClient` that `EncryptionV3` returns, neither needing a cast.
 * Mirrors the approach the Drizzle v3 operators take for the same reason: a
 * nominal `TypedEncryptionClient<S>` parameter would reject a client built for
 * a narrower schema tuple.
 *
 * The two clients differ at runtime on the decrypt paths — the nominal client
 * returns a chainable operation carrying `.audit()`, the typed wrapper returns
 * a plain `Promise<Result<…>>` and takes the table as a second argument. The
 * operation classes handle both; see `DecryptModelOperation`. The consequence
 * for callers is that **audit metadata on decrypt requires the nominal
 * client** — with a client from `EncryptionV3` there is nowhere to put it.
 */
export type DynamoDBEncryptionClient = {
  encryptModel(input: never, table: never): unknown
  bulkEncryptModels(input: never, table: never): unknown
  decryptModel(input: never, table?: never): unknown
  bulkDecryptModels(input: never, table?: never): unknown
}

type ChainableEncryptOperation<T> = {
  audit(data: {
    metadata?: Record<string, unknown>
  }): PromiseLike<
    | { data: T; failure?: never }
    | { data?: never; failure: { message: string; code?: string } }
  >
}

/**
 * @internal Callable view of {@link DynamoDBEncryptionClient}.
 *
 * The public type declares `never` operands so both client shapes satisfy it
 * without a cast; a callable signature cannot be written that both a generic
 * `EncryptionClient` method and a generic `TypedEncryptionClient` method
 * satisfy. The operation classes therefore cast to this shape at the call site
 * — the same split the Drizzle v3 operators use.
 *
 * `decryptModel` is intentionally untyped in its return: the nominal client
 * returns a chainable operation, the typed client a plain promise. See
 * `resolveDecryptResult`.
 */
export type CallableEncryptionClient = {
  encryptModel(
    input: Record<string, unknown>,
    table: AnyEncryptedTable,
  ): ChainableEncryptOperation<Record<string, unknown>>
  bulkEncryptModels(
    input: Record<string, unknown>[],
    table: AnyEncryptedTable,
  ): ChainableEncryptOperation<Record<string, unknown>[]>
  decryptModel(
    input: Record<string, unknown>,
    table?: AnyEncryptedTable,
  ): unknown
  bulkDecryptModels(
    input: Record<string, unknown>[],
    table?: AnyEncryptedTable,
  ): unknown
}

export interface EncryptedDynamoDBConfig {
  /**
   * Either the nominal client from `Encryption(...)` / `Encryption({ schemas,
   * config: { eqlVersion: 3 } })`, or the typed client from `EncryptionV3(...)`.
   * For EQL v3 tables the client must be in v3 mode — `EncryptionV3` forces
   * this; with `Encryption` you must pass `config: { eqlVersion: 3 }` yourself.
   */
  encryptionClient: EncryptionClient | DynamoDBEncryptionClient
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
    table: AnyEncryptedTable,
  ): EncryptModelOperation<T>

  bulkEncryptModels<T extends Record<string, unknown>>(
    items: T[],
    table: AnyEncryptedTable,
  ): BulkEncryptModelsOperation<T>

  decryptModel<T extends Record<string, unknown>>(
    item: Record<string, EncryptedValue | unknown>,
    table: AnyEncryptedTable,
  ): DecryptModelOperation<T>

  bulkDecryptModels<T extends Record<string, unknown>>(
    items: Record<string, EncryptedValue | unknown>[],
    table: AnyEncryptedTable,
  ): BulkDecryptModelsOperation<T>
}
