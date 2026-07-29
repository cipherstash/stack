import type { EncryptedValue } from '@/types'
import { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import { DecryptModelOperation } from './operations/decrypt-model'
import { EncryptModelOperation } from './operations/encrypt-model'
import type {
  AnyEncryptedTable,
  DynamoDBReadOptions,
  EncryptedDynamoDBConfig,
  EncryptedDynamoDBInstance,
} from './types'

/**
 * Fail fast on an EQL version mismatch between the client and the table.
 *
 * A v3 table encrypted through a client that is NOT in EQL v3 mode for it — a
 * v2-mode client, or one initialised for a different schema set — otherwise
 * surfaces only much later as an opaque FFI deserialization error, far from the
 * misconfiguration that caused it.
 *
 * The client does not expose its EQL wire version directly (it is baked into the
 * FFI client at `newClient` time and neither the nominal `EncryptionClient` nor
 * the typed `Encryption` wrapper re-surfaces it). The reliable, public signal
 * both client shapes DO expose is `getEncryptConfig()`: a v3 table can only be
 * encrypted by a client that registered it, and a client built for v3 registers
 * it under its `tableName`. So the guard fires only when we can PROVE the table
 * is absent from a readable config — never on an unreadable one, to avoid a
 * false positive.
 *
 * This runs at the first point where both the client and a concrete table are in
 * hand: the operation methods below, when a table is supplied. `encryptedDynamoDB`
 * itself receives no table, so it cannot check earlier.
 *
 * The one case this could not detect — a client forced to `eqlVersion: 2` while
 * registering a v3 table, emitting v2 wire for an `eql_v3_*` domain — is now
 * refused by `resolveEqlVersion` at client construction, so no such client can
 * reach here.
 */
function assertClientTableVersionMatch(
  encryptionClient: EncryptedDynamoDBConfig['encryptionClient'],
  table: AnyEncryptedTable,
  storedEqlVersion: 2 | 3 = 3,
): void {
  if (storedEqlVersion === 2) {
    if (
      (encryptionClient as { requiresTableForDecrypt?: boolean })
        .requiresTableForDecrypt
    ) {
      throw new Error(
        'encryptedDynamoDB: the @cipherstash/stack/wasm-inline client cannot read DynamoDB attributes stored from EQL v2 because that entry requires registered table-aware decryption. Use the native @cipherstash/stack entry for legacy rows.',
      )
    }
    return
  }

  const getEncryptConfig = (
    encryptionClient as {
      getEncryptConfig?: () => { tables?: Record<string, unknown> } | undefined
    }
  ).getEncryptConfig

  // Without a readable config we cannot prove a mismatch — stay silent rather
  // than false-positive on a client shape that does not expose it.
  if (typeof getEncryptConfig !== 'function') return
  const config = getEncryptConfig.call(encryptionClient)
  if (!config?.tables) return
  if (table.tableName in config.tables) return

  throw new Error(
    `encryptedDynamoDB: EQL version mismatch — the EQL v3 table "${table.tableName}" is not registered with this encryption client, so the client is not in EQL v3 mode for it. A v3 table requires a v3-mode client: build it with Encryption({ schemas: [<table>] }) and pass that client to encryptedDynamoDB. Otherwise encrypt/decrypt fails later inside the FFI with an opaque deserialization error.`,
  )
}

function resolveStoredEqlVersion(options: DynamoDBReadOptions): 2 | 3 {
  const version = options.storedEqlVersion ?? 3
  if (version !== 2 && version !== 3) {
    throw new Error(
      `encryptedDynamoDB: unsupported storedEqlVersion ${String(version)}; expected 2 or 3.`,
    )
  }
  return version
}

/**
 * Create an encrypted DynamoDB helper bound to an `EncryptionClient`.
 *
 * Returns an object with `encryptModel`, `decryptModel`, `bulkEncryptModels`,
 * and `bulkDecryptModels` methods that transparently encrypt/decrypt DynamoDB
 * items according to the provided table schema.
 *
 * Every operation uses an EQL v3 table. To read attributes stored as EQL v2,
 * pass `{ storedEqlVersion: 2 }` to a decrypt method; the table still supplies
 * current column identity and type reconstruction.
 *
 * Only equality is meaningful on DynamoDB: an `hm` term is stored alongside the
 * ciphertext as `<attr>__hmac` and can back a key condition. Ordering and
 * free-text terms have no DynamoDB query surface and are not stored, so values
 * in those domains remain decryptable but not searchable within DynamoDB.
 *
 * @param config - Configuration containing the `encryptionClient` and optional
 *   logging / error-handling callbacks.
 * @returns An {@link EncryptedDynamoDBInstance} with encrypt/decrypt operations.
 *
 * @example EQL v3
 * ```typescript
 * import { Encryption } from "@cipherstash/stack"
 * import { encryptedTable, types } from "@cipherstash/stack/v3"
 * import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"
 *
 * const users = encryptedTable("users", {
 *   email: types.TextEq("email"),  // equality → queryable via email__hmac
 *   name: types.Text("name"),      // storage only
 * })
 *
 * const client = await Encryption({ schemas: [users] })
 * const dynamo = encryptedDynamoDB({ encryptionClient: client })
 *
 * const encrypted = await dynamo.encryptModel({ email: "a@b.com" }, users)
 * ```
 *
 * @example EQL v2 storage (reading existing deployments)
 * ```typescript
 * import { Encryption } from "@cipherstash/stack"
 * import { encryptedDynamoDB } from "@cipherstash/stack/dynamodb"
 * const decrypted = await dynamo.decryptModel(storedItem, users, {
 *   storedEqlVersion: 2,
 * })
 * ```
 */
export function encryptedDynamoDB(
  config: EncryptedDynamoDBConfig,
): EncryptedDynamoDBInstance {
  const { encryptionClient, options } = config

  // The public interface is OVERLOADED per wire version (a v3 overload that
  // knows the storage split, a v2 one that does not). A single generic
  // implementation signature cannot be inferred as satisfying both arms — the
  // v3 overload's return is the derived `EncryptedAttributes` storage split,
  // which the erased implementation (built against `AnyEncryptedTable`) cannot
  // reproduce. So each method is written once against the erased shape and cast
  // to ITS OWN interface member, and the assembled object is annotated with the
  // public type. Nothing about the runtime differs between the overloads — the
  // table decides everything, and it does so at runtime.
  //
  // Why per-method casts rather than one object-level `as`: the object literal
  // is checked against the annotation, so a method renamed/added/removed on the
  // interface (drift between the four impls and the eight-overload public type)
  // now fails to compile — a single `as EncryptedDynamoDBInstance` erased that.
  // What a per-method cast still cannot check is the v3 RETURN precision
  // (`EncryptedAttributes`), for the erasure reason above; that surface is
  // locked instead by `__tests__/dynamodb/client-compat.test-d.ts`.
  const encryptModel = <T extends Record<string, unknown>>(
    item: T,
    table: AnyEncryptedTable,
  ) => {
    assertClientTableVersionMatch(encryptionClient, table)
    return new EncryptModelOperation<T>(encryptionClient, item, table, options)
  }

  const bulkEncryptModels = <T extends Record<string, unknown>>(
    items: T[],
    table: AnyEncryptedTable,
  ) => {
    assertClientTableVersionMatch(encryptionClient, table)
    return new BulkEncryptModelsOperation<T>(
      encryptionClient,
      items,
      table,
      options,
    )
  }

  const decryptModel = <T extends Record<string, unknown>>(
    item: Record<string, EncryptedValue | unknown>,
    table: AnyEncryptedTable,
    readOptions: DynamoDBReadOptions = {},
  ) => {
    const storedEqlVersion = resolveStoredEqlVersion(readOptions)
    assertClientTableVersionMatch(encryptionClient, table, storedEqlVersion)
    return new DecryptModelOperation<T>(
      encryptionClient,
      item,
      table,
      readOptions,
      options,
    )
  }

  const bulkDecryptModels = <T extends Record<string, unknown>>(
    items: Record<string, EncryptedValue | unknown>[],
    table: AnyEncryptedTable,
    readOptions: DynamoDBReadOptions = {},
  ) => {
    const storedEqlVersion = resolveStoredEqlVersion(readOptions)
    assertClientTableVersionMatch(encryptionClient, table, storedEqlVersion)
    return new BulkDecryptModelsOperation<T>(
      encryptionClient,
      items,
      table,
      readOptions,
      options,
    )
  }

  const instance: EncryptedDynamoDBInstance = {
    encryptModel: encryptModel as EncryptedDynamoDBInstance['encryptModel'],
    bulkEncryptModels:
      bulkEncryptModels as EncryptedDynamoDBInstance['bulkEncryptModels'],
    decryptModel: decryptModel as EncryptedDynamoDBInstance['decryptModel'],
    bulkDecryptModels:
      bulkDecryptModels as EncryptedDynamoDBInstance['bulkDecryptModels'],
  }

  return instance
}

export type { AuditConfig } from './operations/base-operation'
export type {
  AnyEncryptedTable,
  DecryptedAttributes,
  DynamoDBEncryptionClient,
  DynamoDBReadOptions,
  EncryptedAttributes,
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
