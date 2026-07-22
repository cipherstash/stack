import { type Result, withResult } from '@byteslice/result'
import { newClient } from '@cipherstash/protect-ffi'
import { validate as uuidValidate } from 'uuid'
import type { AnyV3Table } from '@/eql/v3'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
// `LockContext` is imported type-only so the TSDoc {@link} references in the
// comments below resolve; it is erased at compile time.
import type { LockContext } from '@/identity'
import {
  buildEncryptConfig,
  type EncryptConfig,
  encryptConfigSchema,
  // Imported type-only for the TSDoc {@link} references in the comments below.
  type encryptedColumn,
  type encryptedField,
  type encryptedTable,
} from '@/schema'
import type {
  AuthStrategy,
  BuildableTable,
  BulkDecryptPayload,
  BulkEncryptPayload,
  Client,
  ClientConfig,
  Encrypted,
  EncryptedFromBuildableTable,
  EncryptionClientConfig,
  EncryptOptions,
  EncryptQueryOptions,
  KeysetIdentifier,
  Plaintext,
  ScalarQueryTerm,
} from '@/types'
import { hasBuildColumnKeyMap } from '@/types'
import { logger } from '@/utils/logger'
import { toFfiKeysetIdentifier } from './helpers'
import { isScalarQueryTermArray } from './helpers/type-guards'
import { BatchEncryptQueryOperation } from './operations/batch-encrypt-query'
import { BulkDecryptOperation } from './operations/bulk-decrypt'
import { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import { BulkEncryptOperation } from './operations/bulk-encrypt'
import { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import { DecryptOperation } from './operations/decrypt'
import { DecryptModelOperation } from './operations/decrypt-model'
import { EncryptOperation } from './operations/encrypt'
import { EncryptModelOperation } from './operations/encrypt-model'
import { EncryptQueryOperation } from './operations/encrypt-query'
// `typedClient` wraps the nominal client into the strongly-typed EQL v3 client.
// This is a deliberate circular import with `./v3` (which imports `Encryption`
// from here): both `Encryption` and `typedClient` are hoisted `function`
// declarations, and the only module-eval cross-reference — `EncryptionV3 =
// Encryption` in `./v3` — reads the hoisted `Encryption`, so neither binding is
// observed uninitialised regardless of which module evaluates first.
import { type TypedEncryptionClient, typedClient } from './v3'

// Re-export the operation classes returned by EncryptionClient methods so they
// are part of the public API and appear in the generated reference, allowing
// TSDoc {@link} references and method return types to resolve to real pages.
export {
  BatchEncryptQueryOperation,
  BulkDecryptModelsOperation,
  BulkDecryptOperation,
  BulkEncryptModelsOperation,
  BulkEncryptOperation,
  DecryptModelOperation,
  DecryptOperation,
  EncryptModelOperation,
  EncryptOperation,
  EncryptQueryOperation,
}

export const noClientError = () =>
  new Error(
    'The Encryption client has not been initialized. Please call init() before using the client.',
  )

/**
 * Resolve the EQL wire version for a client from its schema set.
 *
 * One FFI client emits exactly one wire format, so the whole schema set must
 * agree. EQL v3 tables (from `@cipherstash/stack/v3`) are detected by their
 * `buildColumnKeyMap()` marker — v2 tables don't have one:
 *
 * - every schema is v3 → `3`;
 * - no schema is v3 → `undefined`, leaving scalar-only schemas on the FFI's v2
 *   default;
 * - a mix of the two → throws: the v2 tables target `eql_v2_encrypted`
 *   columns and the v3 tables target `eql_v3` domains, so no single wire
 *   format serves both. Split them across two clients.
 *
 * An explicit `config.eqlVersion` bypasses version detection (the wire format
 * is then unambiguous — e.g. writing v2 wire from a v3 schema set during a
 * migration), but mixed schemas and legacy v2 SteVec schemas still throw.
 *
 * @internal exported for unit-test coverage of the detection matrix.
 */
export function resolveEqlVersion(
  schemas: readonly BuildableTable[],
  explicit?: 2 | 3,
): 2 | 3 | undefined {
  const v3Count = schemas.filter(hasBuildColumnKeyMap).length

  if (v3Count > 0 && v3Count < schemas.length) {
    throw new Error(
      '[encryption]: cannot mix EQL v2 and EQL v3 tables in one client — one client emits exactly one wire format. Create separate clients for the v2 and v3 schemas.',
    )
  }

  // cipherstash-client 0.42 removed the EQL v2 SteVec selector envelope.
  // protect-ffi 0.30 therefore cannot emit v2 searchable-JSON values at all;
  // allowing this legacy schema through would either fail opaquely in the FFI
  // or emit v3 data for an eql_v2 column. Fail at setup with a migration steer.
  if (
    v3Count === 0 &&
    schemas.some((schema) =>
      Object.values(schema.build().columns).some(
        (column) => column.indexes?.ste_vec !== undefined,
      ),
    )
  ) {
    throw new Error(
      '[encryption]: searchableJson() on the legacy EQL v2 schema is not supported by protect-ffi 0.30. Migrate the column to the EQL v3 types.Json() domain.',
    )
  }

  if (explicit !== undefined) {
    return explicit
  }

  return v3Count === 0 ? undefined : 3
}

/** The EncryptionClient is the main entry point for interacting with the CipherStash Encryption library.
 * It provides methods for encrypting and decrypting individual values, as well as models (objects) and bulk operations.
 *
 * The client must be initialized using the {@link Encryption} function before it can be used.
 */
export class EncryptionClient {
  private client: Client
  private encryptConfig: EncryptConfig | undefined

  /**
   * Initializes the EncryptionClient with the provided configuration.
   * @internal
   * @param config - The configuration object for initializing the client.
   * @returns A promise that resolves to a {@link Result} containing the initialized EncryptionClient or an {@link EncryptionError}.
   **/
  async init(config: {
    encryptConfig: EncryptConfig
    workspaceCrn?: string
    accessKey?: string
    clientId?: string
    clientKey?: string
    keyset?: KeysetIdentifier
    authStrategy?: AuthStrategy
    eqlVersion?: 2 | 3
  }): Promise<Result<EncryptionClient, EncryptionError>> {
    return await withResult(
      async () => {
        const validated: EncryptConfig = encryptConfigSchema.parse(
          config.encryptConfig,
        )

        logger.debug(
          'Initializing the Encryption client with the following config:',
          {
            encryptConfig: validated,
          },
        )

        // newClient handles env var fallback internally via withEnvCredentials,
        // so we pass config values through without manual fallback here.
        // When `authStrategy` is supplied, protect-ffi invokes its getToken()
        // on every ZeroKMS request instead of building an AutoStrategy
        // from the credentials in clientOpts (the clientKey is still used
        // for encryption). Passing `strategy: undefined` is equivalent to
        // omitting it, so the default credentials path is unaffected.
        // `eqlVersion` selects the wire format `encrypt`/`encryptQuery`
        // emit (protect-ffi 0.27+); `eqlVersion: undefined` is likewise
        // equivalent to omitting it, leaving the FFI's v2 default — and
        // its byte-identical v2 output — untouched.
        this.client = await newClient({
          encryptConfig: validated,
          clientOpts: {
            workspaceCrn: config.workspaceCrn,
            accessKey: config.accessKey,
            clientId: config.clientId,
            clientKey: config.clientKey,
            keyset: toFfiKeysetIdentifier(config.keyset),
          },
          strategy: config.authStrategy,
          eqlVersion: config.eqlVersion,
        })

        this.encryptConfig = validated

        logger.debug('Successfully initialized the Encryption client.')
        return this
      },
      (error: unknown) => ({
        type: EncryptionErrorTypes.ClientInitError,
        message: (error as Error).message,
      }),
    )
  }

  /**
   * Encrypt a value - returns a promise which resolves to an encrypted value.
   *
   * @param plaintext - The plaintext value to be encrypted.
   * @param opts - Options specifying the column (or nested field) and table for encryption. See {@link EncryptOptions}.
   * @returns An EncryptOperation that can be awaited or chained with additional methods.
   *
   * @example
   * The following example demonstrates how to encrypt a value using the Encryption client.
   * It includes defining an encryption schema with {@link encryptedTable} and {@link encryptedColumn},
   * initializing the client with {@link Encryption}, and performing the encryption.
   *
   * `encrypt` returns an {@link EncryptOperation} which can be awaited to get a {@link Result}
   * which can either be the encrypted value or an {@link EncryptionError}.
   *
   * ```typescript
   * // Define encryption schema
   * import { Encryption } from "@cipherstash/stack"
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   * const userSchema = encryptedTable("users", {
   *  email: encryptedColumn("email"),
   * });
   *
   * // Initialize Encryption client
   * const client = await Encryption({ schemas: [userSchema] })
   *
   * // Encrypt a value
   * const encryptedResult = await client.encrypt(
   *  "person@example.com",
   *  { column: userSchema.email, table: userSchema }
   * )
   *
   * // Handle encryption result
   * if (encryptedResult.failure) {
   *   throw new Error(`Encryption failed: ${encryptedResult.failure.message}`);
   * }
   *
   * console.log("Encrypted data:", encryptedResult.data);
   * ```
   *
   * @example
   * When encrypting data, a {@link LockContext} can be provided to tie the encryption to a specific user or session.
   * This ensures that the same lock context is required for decryption.
   *
   * The following example demonstrates how to create a lock context using a user's JWT token
   * and use it during encryption.
   *
   * ```typescript
   * // Define encryption schema and initialize client as above
   *
   * // Create a lock for the user's `sub` claim from their JWT
   * const lc = new LockContext();
   * const lockContext = await lc.identify(userJwt);
   *
   * if (lockContext.failure) {
   *   // Handle the failure
   * }
   *
   * // Encrypt a value with the lock context
   * // Decryption will then require the same lock context
   * const encryptedResult = await client.encrypt(
   *  "person@example.com",
   *  { column: userSchema.email, table: userSchema }
   * )
   *  .withLockContext(lockContext)
   * ```
   *
   * @see {@link EncryptOptions}
   * @see {@link Result}
   * @see {@link encryptedTable}
   * @see {@link encryptedColumn}
   * @see {@link encryptedField}
   * @see {@link LockContext}
   * @see {@link EncryptOperation}
   */
  encrypt(plaintext: Plaintext, opts: EncryptOptions): EncryptOperation {
    return new EncryptOperation(this.client, plaintext, opts)
  }

  /**
   * Encrypt a query value - returns a promise which resolves to an encrypted query value.
   *
   * @param plaintext - The plaintext value to be encrypted for querying.
   * @param opts - Options specifying the column, table, and optional queryType for encryption.
   * @returns An EncryptQueryOperation that can be awaited or chained with additional methods.
   *
   * @example
   * The following example demonstrates how to encrypt a query value using the Encryption client.
   *
   * ```typescript
   * // Define encryption schema
   * import { Encryption } from "@cipherstash/stack"
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   * const userSchema = encryptedTable("users", {
   *  email: encryptedColumn("email").equality(),
   * });
   *
   * // Initialize Encryption client
   * const client = await Encryption({ schemas: [userSchema] })
   *
   * // Encrypt a query value
   * const encryptedResult = await client.encryptQuery(
   *  "person@example.com",
   *  { column: userSchema.email, table: userSchema, queryType: 'equality' }
   * )
   *
   * // Handle encryption result
   * if (encryptedResult.failure) {
   *   throw new Error(`Encryption failed: ${encryptedResult.failure.message}`);
   * }
   *
   * console.log("Encrypted query:", encryptedResult.data);
   * ```
   *
   * @example
   * The queryType can be auto-inferred from the column's configured indexes:
   *
   * ```typescript
   * // When queryType is omitted, it will be inferred from the column's indexes
   * const encryptedResult = await client.encryptQuery(
   *  "person@example.com",
   *  { column: userSchema.email, table: userSchema }
   * )
   * ```
   *
   * @see {@link EncryptQueryOperation}
   *
   * **JSONB columns (searchableJson):**
   * When `queryType` is omitted on a `searchableJson()` column, the query operation is inferred:
   * - String plaintext → `steVecSelector` (JSONPath queries like `'$.user.email'`)
   * - Object/Array plaintext → default SteVec containment (for example `{ role: 'admin' }`)
   */
  encryptQuery(
    plaintext: Plaintext,
    opts: EncryptQueryOptions,
  ): EncryptQueryOperation

  /**
   * Encrypt multiple values for use in queries (batch operation).
   * @param terms - Array of query terms to encrypt
   */
  encryptQuery(terms: readonly ScalarQueryTerm[]): BatchEncryptQueryOperation

  encryptQuery(
    plaintextOrTerms: Plaintext | readonly ScalarQueryTerm[],
    opts?: EncryptQueryOptions,
  ): EncryptQueryOperation | BatchEncryptQueryOperation {
    // Discriminate between ScalarQueryTerm[] and Plaintext (which can also be an
    // array) using a type guard function. Only route to batch mode when no opts
    // are supplied — an explicit EncryptQueryOptions forces the single-plaintext
    // path even if the plaintext value happens to be an array.
    if (!opts && isScalarQueryTermArray(plaintextOrTerms)) {
      return new BatchEncryptQueryOperation(this.client, plaintextOrTerms)
    }

    // Handle empty arrays: if opts provided, treat as single value; otherwise batch mode
    // This maintains backward compatibility for encryptQuery([]) while allowing
    // encryptQuery([], opts) to encrypt an empty array as a single value
    if (
      Array.isArray(plaintextOrTerms) &&
      plaintextOrTerms.length === 0 &&
      !opts
    ) {
      return new BatchEncryptQueryOperation(
        this.client,
        [] as readonly ScalarQueryTerm[],
      )
    }

    if (!opts) {
      throw new Error('EncryptQueryOptions are required')
    }

    return new EncryptQueryOperation(
      this.client,
      plaintextOrTerms as Plaintext,
      opts,
    )
  }

  /**
   * Decryption - returns a promise which resolves to a decrypted value.
   *
   * @param encryptedData - The encrypted data to be decrypted.
   * @returns A DecryptOperation that can be awaited or chained with additional methods.
   *
   * @example
   * The following example demonstrates how to decrypt a value that was previously encrypted using the {@link encrypt} method.
   * It includes encrypting a value first, then decrypting it, and handling the result.
   *
   * ```typescript
   * const encryptedData = await client.encrypt(
   *  "person@example.com",
   *  { column: "email", table: "users" }
   * )
   * const decryptResult = await client.decrypt(encryptedData)
   * if (decryptResult.failure) {
   *   throw new Error(`Decryption failed: ${decryptResult.failure.message}`);
   * }
   * console.log("Decrypted data:", decryptResult.data);
   * ```
   *
   * @example
   * Provide a lock context when decrypting:
   * ```typescript
   *    await client.decrypt(encryptedData)
   *      .withLockContext(lockContext)
   * ```
   *
   * @remarks
   * The public input type rejects null, but at runtime `decrypt` will
   * short-circuit and return null when given a null ciphertext
   * (defense in depth for legacy / manually-NULLed DB rows reached via
   * casts or dynamic field walking). The narrow return type holds for
   * any caller that respects the input contract.
   *
   * @see {@link LockContext}
   * @see {@link DecryptOperation}
   */
  decrypt(encryptedData: Encrypted): DecryptOperation {
    return new DecryptOperation(this.client, encryptedData)
  }

  /**
   * Encrypt a model (object) based on the table schema.
   *
   * Only fields whose keys match columns defined in the table schema are encrypted.
   * All other fields are passed through unchanged. Returns a thenable operation
   * that supports `.withLockContext()` for identity-aware encryption.
   *
   * The return type is **schema-aware**: fields matching the table schema are
   * typed as `Encrypted`, while other fields retain their original types. For
   * best results, let TypeScript infer the type parameters from the arguments
   * rather than providing an explicit type argument.
   *
   * @param input - The model object with plaintext values to encrypt.
   * @param table - The table schema defining which fields to encrypt.
   * @returns An `EncryptModelOperation` that can be awaited to get a `Result`
   *   containing the model with schema-defined fields typed as `Encrypted`,
   *   or an `EncryptionError`.
   *
   * @example
   * ```typescript
   * import { Encryption } from "@cipherstash/stack"
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * type User = { id: string; email: string; createdAt: Date }
   *
   * const usersSchema = encryptedTable("users", {
   *   email: encryptedColumn("email").equality(),
   * })
   *
   * const client = await Encryption({ schemas: [usersSchema] })
   *
   * // Let TypeScript infer the return type from the schema.
   * // result.data.email is typed as `Encrypted`, result.data.id stays `string`.
   * const result = await client.encryptModel(
   *   { id: "user_123", email: "alice@example.com", createdAt: new Date() },
   *   usersSchema,
   * )
   *
   * if (result.failure) {
   *   console.error(result.failure.message)
   * } else {
   *   console.log(result.data.id)    // string
   *   console.log(result.data.email) // Encrypted
   * }
   * ```
   */
  encryptModel<T extends Record<string, unknown>, Table extends BuildableTable>(
    input: T,
    table: Table,
  ): EncryptModelOperation<EncryptedFromBuildableTable<T, Table>> {
    return new EncryptModelOperation(
      this.client,
      input as Record<string, unknown>,
      table,
    )
  }

  /**
   * Decrypt a model (object) whose fields contain encrypted values.
   *
   * Identifies encrypted fields automatically and decrypts them, returning the
   * model with plaintext values. Returns a thenable operation that supports
   * `.withLockContext()` for identity-aware decryption.
   *
   * @param input - The model object with encrypted field values.
   * @returns A `DecryptModelOperation<T>` that can be awaited to get a `Result`
   *   containing the model with decrypted plaintext fields, or an `EncryptionError`.
   *
   * @example
   * ```typescript
   * // Decrypt a previously encrypted model
   * const decrypted = await client.decryptModel<User>(encryptedUser)
   *
   * if (decrypted.failure) {
   *   console.error(decrypted.failure.message)
   * } else {
   *   console.log(decrypted.data.email) // "alice@example.com"
   * }
   *
   * // With a lock context
   * const decrypted = await client
   *   .decryptModel<User>(encryptedUser)
   *   .withLockContext(lockContext)
   * ```
   */
  decryptModel<T extends Record<string, unknown>>(
    input: T,
  ): DecryptModelOperation<T> {
    return new DecryptModelOperation(this.client, input)
  }

  /**
   * Encrypt multiple models (objects) in a single bulk operation.
   *
   * Performs a single call to ZeroKMS regardless of the number of models,
   * while still using a unique key for each encrypted value. Only fields
   * matching the table schema are encrypted; other fields pass through unchanged.
   *
   * The return type is **schema-aware**: fields matching the table schema are
   * typed as `Encrypted`, while other fields retain their original types. For
   * best results, let TypeScript infer the type parameters from the arguments.
   *
   * @param input - An array of model objects with plaintext values to encrypt.
   * @param table - The table schema defining which fields to encrypt.
   * @returns A `BulkEncryptModelsOperation` that can be awaited to get a `Result`
   *   containing an array of models with schema-defined fields typed as `Encrypted`,
   *   or an `EncryptionError`.
   *
   * @example
   * ```typescript
   * import { Encryption } from "@cipherstash/stack"
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * type User = { id: string; email: string }
   *
   * const usersSchema = encryptedTable("users", {
   *   email: encryptedColumn("email"),
   * })
   *
   * const client = await Encryption({ schemas: [usersSchema] })
   *
   * // Let TypeScript infer the return type from the schema.
   * // Each item's email is typed as `Encrypted`, id stays `string`.
   * const result = await client.bulkEncryptModels(
   *   [
   *     { id: "1", email: "alice@example.com" },
   *     { id: "2", email: "bob@example.com" },
   *   ],
   *   usersSchema,
   * )
   *
   * if (!result.failure) {
   *   console.log(result.data) // array of models with encrypted email fields
   * }
   * ```
   */
  bulkEncryptModels<
    T extends Record<string, unknown>,
    Table extends BuildableTable,
  >(
    input: Array<T>,
    table: Table,
  ): BulkEncryptModelsOperation<EncryptedFromBuildableTable<T, Table>> {
    return new BulkEncryptModelsOperation(
      this.client,
      input as Array<Record<string, unknown>>,
      table,
    )
  }

  /**
   * Decrypt multiple models (objects) in a single bulk operation.
   *
   * Performs a single call to ZeroKMS regardless of the number of models,
   * restoring all encrypted fields to their original plaintext values.
   *
   * @param input - An array of model objects with encrypted field values.
   * @returns A `BulkDecryptModelsOperation<T>` that can be awaited to get a `Result`
   *   containing an array of models with decrypted plaintext fields, or an `EncryptionError`.
   *
   * @example
   * ```typescript
   * const encryptedUsers = encryptedResult.data // from bulkEncryptModels
   *
   * const result = await client.bulkDecryptModels<User>(encryptedUsers)
   *
   * if (!result.failure) {
   *   for (const user of result.data) {
   *     console.log(user.email) // plaintext email
   *   }
   * }
   *
   * // With a lock context
   * const result = await client
   *   .bulkDecryptModels<User>(encryptedUsers)
   *   .withLockContext(lockContext)
   * ```
   */
  bulkDecryptModels<T extends Record<string, unknown>>(
    input: Array<T>,
  ): BulkDecryptModelsOperation<T> {
    return new BulkDecryptModelsOperation(this.client, input)
  }

  /**
   * Encrypt multiple plaintext values in a single bulk operation.
   *
   * Each value is encrypted with its own unique key via a single call to ZeroKMS.
   * Values can include optional `id` fields for correlating results back to
   * your application data.
   *
   * @param plaintexts - An array of objects with `plaintext` (and optional `id`) fields.
   * @param opts - Options specifying the target column (or nested {@link encryptedField}) and table. See {@link EncryptOptions}.
   * @returns A `BulkEncryptOperation` that can be awaited to get a `Result`
   *   containing an array of `{ id?, data: Encrypted }` objects, or an `EncryptionError`.
   *
   * @example
   * ```typescript
   * import { Encryption } from "@cipherstash/stack"
   * import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema"
   *
   * const users = encryptedTable("users", {
   *   email: encryptedColumn("email"),
   * })
   * const client = await Encryption({ schemas: [users] })
   *
   * const result = await client.bulkEncrypt(
   *   [
   *     { id: "u1", plaintext: "alice@example.com" },
   *     { id: "u2", plaintext: "bob@example.com" },
   *   ],
   *   { column: users.email, table: users },
   * )
   *
   * if (!result.failure) {
   *   // result.data = [{ id: "u1", data: Encrypted }, { id: "u2", data: Encrypted }, ...]
   *   console.log(result.data)
   * }
   * ```
   */
  bulkEncrypt(
    plaintexts: BulkEncryptPayload,
    opts: EncryptOptions,
  ): BulkEncryptOperation {
    return new BulkEncryptOperation(this.client, plaintexts, opts)
  }

  /**
   * Decrypt multiple encrypted values in a single bulk operation.
   *
   * Performs a single call to ZeroKMS to decrypt all values. The result uses
   * a multi-status pattern: each item in the returned array has either a `data`
   * field (success) or an `error` field (failure), allowing graceful handling
   * of partial failures.
   *
   * @param encryptedPayloads - An array of objects with `data` (encrypted payload) and optional `id` fields.
   * @returns A `BulkDecryptOperation` that can be awaited to get a `Result`
   *   containing an array of `{ id?, data: plaintext }` or `{ id?, error: string }` objects,
   *   or an `EncryptionError` if the entire operation fails.
   *
   * @example
   * ```typescript
   * const encrypted = await client.bulkEncrypt(plaintexts, { column: users.email, table: users })
   *
   * const result = await client.bulkDecrypt(encrypted.data)
   *
   * if (!result.failure) {
   *   for (const item of result.data) {
   *     if ("data" in item) {
   *       console.log(`${item.id}: ${item.data}`)
   *     } else {
   *       console.error(`${item.id} failed: ${item.error}`)
   *     }
   *   }
   * }
   * ```
   */
  bulkDecrypt(encryptedPayloads: BulkDecryptPayload): BulkDecryptOperation {
    return new BulkDecryptOperation(this.client, encryptedPayloads)
  }

  /**
   * Get the encrypt config object.
   *
   * @returns The encrypt config object.
   */
  getEncryptConfig(): EncryptConfig | undefined {
    return this.encryptConfig
  }
}

// Emit the `config.strategy` → `config.authStrategy` rename warning at most
// once per process so repeated `Encryption()` calls don't spam the console.
let warnedStrategyDeprecated = false
function warnStrategyDeprecated(): void {
  if (warnedStrategyDeprecated) return
  warnedStrategyDeprecated = true
  console.warn(
    '[encryption]: `config.strategy` is deprecated and will be removed in a future release — use `config.authStrategy` instead.',
  )
}

/**
 * Reset the once-per-process deprecation-warning latch. Test-only hook so
 * suites can assert the warning fires deterministically, independent of test
 * ordering. Not re-exported from the package entry, so it stays off the public
 * API surface.
 * @internal
 */
export function __resetStrategyDeprecationWarningForTests(): void {
  warnedStrategyDeprecated = false
}

/**
 * Creates and initializes an Encryption client for encrypting and decrypting data with CipherStash.
 *
 * Provide at least one schema (from {@link encryptedTable}) so the client knows which tables and
 * columns to use:
 *
 * ```typescript
 * import { Encryption, encryptedTable, encryptedColumn } from "@cipherstash/stack"
 *
 * const users = encryptedTable("users", { email: encryptedColumn("email") })
 * const client = await Encryption({ schemas: [users] })
 * const result = await client.encrypt("alice@example.com", { column: users.email, table: users })
 * ```
 *
 * ## Authentication
 *
 * The snippets in this section reuse the `users` schema from the example above, and
 * `workspaceCrn` / `accessKey` stand in for your own workspace credentials (from the
 * [dashboard](https://dashboard.cipherstash.com) or the `CS_*` variables below).
 *
 * By default the client uses the `auto` auth strategy. `auto` first looks for the `CS_*`
 * environment variables (see below) and, if they are not set, falls back to the local **dev
 * profile** on your machine. The dev profile also supplies the client key, so during local
 * development you generally don't need to set any environment variables at all.
 *
 * ### Local development — create a dev profile
 *
 * Log in once to create the dev profile that `auto` picks up automatically:
 *
 * ```bash
 * npx stash auth login
 * ```
 *
 * ### Production / CI — environment variables
 *
 * In production and CI you typically authenticate with the four `CS_*` environment variables
 * instead of a dev profile. Developers can obtain these values from the
 * [CipherStash dashboard](https://dashboard.cipherstash.com):
 *
 * | Environment variable   | Description                                                                    |
 * | ---------------------- | ------------------------------------------------------------------------------ |
 * | `CS_WORKSPACE_CRN`     | The workspace Cloud Resource Name (CRN) that identifies your workspace.         |
 * | `CS_CLIENT_ID`         | The client identifier issued when you create an access key.                    |
 * | `CS_CLIENT_KEY`        | The client key material combined with ZeroKMS to perform encryption.           |
 * | `CS_CLIENT_ACCESS_KEY` | The API access key used to authenticate requests to CipherStash.               |
 *
 * When these are set, `auto` uses them in preference to the local dev profile.
 *
 * ### Custom auth strategies — `config.authStrategy`
 *
 * For finer control, pass an explicit strategy via `config.authStrategy` (from `@cipherstash/auth`,
 * re-exported by `@cipherstash/stack`). See the `@cipherstash/auth` package for the full list. Two
 * common choices:
 *
 * `AccessKeyStrategy` — like `auto`, but only ever uses an access key; it never falls back to the
 * local dev profile. Ideal for services and CI:
 *
 * ```typescript
 * import { Encryption, AccessKeyStrategy } from "@cipherstash/stack"
 *
 * const client = await Encryption({
 *   schemas: [users],
 *   config: {
 *     authStrategy: AccessKeyStrategy.create(workspaceCrn, accessKey),
 *   },
 * })
 * ```
 *
 * `OidcFederationStrategy` — authenticate end users through your own identity provider (Supabase,
 * Clerk, Auth0 or Okta) by federating their OIDC JWT into a CipherStash token. Add the provider to
 * your workspace first at
 * [dashboard.cipherstash.com/workspaces/_/oidc-providers](https://dashboard.cipherstash.com/workspaces/_/oidc-providers)
 * (the `_` in the URL resolves to whichever workspace you select):
 *
 * ```typescript
 * import { Encryption, OidcFederationStrategy } from "@cipherstash/stack"
 *
 * // Authenticate every ZeroKMS request as the signed-in user.
 * const client = await Encryption({
 *   schemas: [users],
 *   config: {
 *     authStrategy: OidcFederationStrategy.create(workspaceCrn, () => getUserJwt()),
 *   },
 * })
 * ```
 *
 * ### Lock context (identity-bound encryption)
 *
 * Lock context is an **additional** capability layered on top of `OidcFederationStrategy`: it
 * requires that strategy, but `OidcFederationStrategy` does not require lock context. It binds a
 * value to a claim from the user's JWT (typically `sub`) so that only the user who encrypted a
 * value can decrypt it:
 *
 * ```typescript
 * // Bind the data key to the user's `sub` claim.
 * const result = await client
 *   .encrypt("alice@example.com", { column: users.email, table: users })
 *   .withLockContext({ identityClaim: ["sub"] })
 * ```
 *
 * Because the lock is tied to a specific end user's identity, `AccessKeyStrategy` (which
 * authenticates a service, not a user) is not valid for lock context — there is no user `sub`
 * claim to bind to.
 *
 * ## Keysets (multi-tenant isolation)
 *
 * Pass `config.keyset` to encrypt under a specific **keyset** — a named or UUID-identified keyspace
 * that gives each tenant its own cryptographic isolation, so data encrypted under one keyset cannot
 * be decrypted under another. Create and manage keysets in the
 * [dashboard](https://dashboard.cipherstash.com/workspaces/_/keysets) (the `_` in the URL resolves
 * to whichever workspace you select); omit `config.keyset` to use the workspace's default keyset.
 *
 * ```typescript
 * // `users` is the schema from the first example above.
 * const client = await Encryption({
 *   schemas: [users],
 *   config: {
 *     keyset: { name: "tenant-a" }, // or { id: "<uuid>" }
 *   },
 * })
 * ```
 *
 * A client is bound to a single keyset for its lifetime, so multi-tenant applications use **one
 * `Encryption()` client per tenant**. Keysets are orthogonal to `authStrategy` and lock context —
 * they isolate a whole tenant's *keyspace* (coarse, fixed per client), whereas lock context binds
 * an individual value to a user's identity claim (fine-grained, per operation) — and can be
 * combined with both.
 *
 * @param config - Initialization options. Must include `schemas`; optionally include `config` for
 *   credentials and authentication. Logging is configured via the `STASH_STACK_LOG` environment
 *   variable (`debug | info | error`, default: `error`).
 * @returns A Promise that resolves to an initialized {@link EncryptionClient} ready for
 *   {@link EncryptionClient.encrypt}, {@link EncryptionClient.decrypt}, and related operations.
 *
 * @throws Throws if `schemas` is empty, or if a keyset `id` is supplied but is not a valid UUID.
 *   Also throws if the client fails to initialize (e.g. invalid credentials or config).
 *
 * @see {@link EncryptionClientConfig} for full config options.
 * @see {@link ClientConfig.authStrategy} for the auth strategy field.
 * @see {@link EncryptionClient} for available methods after initialization.
 */
// Overload 1 — v3-typed: an array literal of concrete EQL v3 tables (from
// `@cipherstash/stack/v3`) yields the strongly-typed {@link TypedEncryptionClient},
// the collapse of the former `EncryptionV3`. The wire format is forced to v3.
export function Encryption<const S extends readonly AnyV3Table[]>(config: {
  schemas: S
  config?: ClientConfig
}): Promise<TypedEncryptionClient<S>>
// Overload 2 — nominal: loose/dynamic schemas (introspection-derived, e.g.
// stack-supabase) or EQL v2 tables yield the generation-neutral
// {@link EncryptionClient}, which auto-detects its wire version. Declared LAST
// so `Parameters<typeof Encryption>` / `ReturnType<typeof Encryption>` resolve
// to this signature (stack-supabase casts its schemas against it).
export function Encryption(
  config: EncryptionClientConfig,
): Promise<EncryptionClient>
export async function Encryption(
  config: EncryptionClientConfig,
): Promise<unknown> {
  const { schemas, config: clientConfig } = config

  if (!schemas.length) {
    throw new Error(
      '[encryption]: At least one encryptedTable must be provided to initialize the encryption client',
    )
  }

  if (
    clientConfig?.keyset &&
    'id' in clientConfig.keyset &&
    !uuidValidate(clientConfig.keyset.id)
  ) {
    throw new Error(
      '[encryption]: Invalid UUID provided for keyset id. Must be a valid UUID.',
    )
  }

  // Resolve the auth strategy, honouring the deprecated `strategy` alias.
  // Warn whenever the deprecated field is present at all — even alongside
  // `authStrategy` — so the leftover field gets cleaned up. `authStrategy`
  // still wins when both are set.
  if (clientConfig?.strategy) {
    warnStrategyDeprecated()
  }
  const authStrategy = clientConfig?.authStrategy ?? clientConfig?.strategy

  const client = new EncryptionClient()
  const encryptConfig = buildEncryptConfig(...schemas)

  // A schema set of exclusively concrete EQL v3 tables is the typed-client path
  // (the collapse of the former `EncryptionV3`). Every other set — EQL v2 tables,
  // or the introspection-derived loose tables stack-supabase passes — stays
  // nominal.
  const isV3Only = schemas.every(hasBuildColumnKeyMap)

  // Resolve the wire format: an explicit `config.eqlVersion` wins (the retained
  // migration escape hatch — e.g. deliberately writing v2 wire from a v3 schema
  // set), otherwise it is auto-detected (v3 tables → 3, v2 tables → the FFI's v2
  // default). A mixed v2 + v3 schema set throws inside `resolveEqlVersion`.
  const eqlVersion = resolveEqlVersion(schemas, clientConfig?.eqlVersion)

  const result = await client.init({
    encryptConfig,
    ...clientConfig,
    authStrategy,
    eqlVersion,
  })

  if (result.failure) {
    throw new Error(`[encryption]: ${result.failure.message}`)
  }

  // Return the typed client only when the client is genuinely in EQL v3 mode: an
  // all-v3 schema set that resolved to the v3 wire format. A caller that forced
  // `eqlVersion: 2` over v3 schemas gets the nominal client for that deliberate,
  // low-level v2-wire migration path (the typed client cannot encrypt v3 columns
  // in v2 mode anyway).
  return isV3Only && eqlVersion === 3
    ? typedClient(result.data, ...(schemas as unknown as readonly AnyV3Table[]))
    : result.data
}
