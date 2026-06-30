import type {
  AuthStrategy,
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
  JsPlaintext,
  newClient,
  QueryOpName,
} from '@cipherstash/protect-ffi'
import type {
  ColumnSchema,
  EncryptedColumn,
  EncryptedField,
  EncryptedTableColumn,
  // Imported type-only for the TSDoc {@link} references in the comments below.
  encryptedColumn,
  encryptedField,
} from '@/schema'

/**
 * A pluggable authentication strategy for ZeroKMS requests. Any object
 * with a `getToken(): Promise<{ token: string }>` method satisfies it —
 * notably the strategies from `@cipherstash/auth`: `OidcFederationStrategy`
 * (per-user, identity-bound encryption) and `AccessKeyStrategy`
 * (service-to-service / CI). When supplied to {@link ClientConfig.strategy},
 * `getToken()` is invoked on every ZeroKMS request, taking precedence over
 * the credentials-derived default.
 *
 * @see ClientConfig.strategy
 */
export type { AuthStrategy }

// ---------------------------------------------------------------------------
// Branded type utilities
// ---------------------------------------------------------------------------

/** Brand symbol for nominal typing */
declare const __brand: unique symbol

/** Creates a branded type that is structurally incompatible with the base type */
type Brand<T, B extends string> = T & { readonly [__brand]: B }

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

export type Client = Awaited<ReturnType<typeof newClient>> | undefined

/** A branded type representing encrypted data. Cannot be accidentally used as plaintext. */
export type EncryptedValue = Brand<CipherStashEncrypted, 'encrypted'>

/** Structural type representing encrypted data stored in the database. Always
 * carries a ciphertext. See also `EncryptedValue` for branded nominal typing,
 * and {@link EncryptedQuery} for the search-term shape returned by
 * `encryptQuery`. */
export type Encrypted = CipherStashEncrypted

/** Structural type representing an encrypted query term (search needle)
 * returned by `encryptQuery` / `encryptQueryBulk` for scalar
 * (`unique` / `match` / `ore`) lookups and `ste_vec_selector` JSON path
 * queries. Carries no ciphertext — matched against stored values, never
 * decrypted. JSON containment queries (`ste_vec_term`) return a
 * storage-shaped {@link Encrypted} payload instead. */
export type EncryptedQuery = CipherStashEncryptedQuery

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

export type KeysetIdentifier = { name: string } | { id: string }

export type ClientConfig = {
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

  /**
   * An optional authentication strategy for ZeroKMS requests, from
   * `@cipherstash/auth` (re-exported by `@cipherstash/stack`). When provided,
   * its `getToken()` is invoked on every ZeroKMS request and takes precedence
   * over the credentials-derived default strategy (the `clientKey` is still
   * required for encryption). Use:
   *
   * - `OidcFederationStrategy` for per-user, identity-bound encryption —
   *   federates an end user's OIDC JWT into a CTS service token, so requests
   *   authenticate as that user. Pair with `.withLockContext({ identityClaim })`
   *   to bind the data key to a claim. This replaces the older
   *   `LockContext.identify()` ceremony.
   * - `AccessKeyStrategy` for service-to-service / CI, or any custom
   *   `{ getToken() }` object for bespoke token acquisition / caching.
   *
   * Leave unset to let the client build its default strategy from
   * `workspaceCrn` / `accessKey` / `clientId` / `clientKey` (or the
   * corresponding `CS_*` environment variables).
   *
   * @see {@link AuthStrategy}
   */
  strategy?: AuthStrategy
}

type AtLeastOneCsTable<T> = [T, ...T[]]

/** Structural contract for a column builder the client can consume for STORAGE
 *  (`encrypt`). Satisfied by v2 `EncryptedColumn` / `EncryptedField` AND v3
 *  `EncryptedTextSearchColumn` — fields ARE encryptable, so this stays wide. */
export interface BuildableColumn {
  getName(): string
  build(): ColumnSchema
}

/** Structural contract for a column the client can consume for QUERIES
 *  (`encryptQuery` / search terms). Narrower than `BuildableColumn`: it must
 *  EXCLUDE non-queryable `EncryptedField` (a field has no indexes). A v2
 *  `EncryptedColumn` qualifies via the nominal arm; a v3 queryable concrete
 *  type qualifies via the `getEqlType()` structural arm; `EncryptedField` (no
 *  `getEqlType`, not an `EncryptedColumn`) is rejected. */
export type BuildableQueryColumn =
  | EncryptedColumn
  | (BuildableColumn & { getEqlType(): string })

/** Structural contract for a table builder the client can consume. Satisfied by
 *  v2 and v3 `EncryptedTable` alike. */
export interface BuildableTable {
  tableName: string
  build(): { tableName: string; columns: Record<string, ColumnSchema> }
}

export type EncryptionClientConfig = {
  schemas: AtLeastOneCsTable<BuildableTable>
  config?: ClientConfig
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt operation options and results
// ---------------------------------------------------------------------------

/**
 * Options for single-value encrypt operations.
 * Use a column from your table schema (from {@link encryptedColumn}) or a nested
 * field (from {@link encryptedField}) as the target for encryption.
 */
export type EncryptOptions = {
  /** The column or nested field to encrypt into. From {@link EncryptedColumn} or {@link EncryptedField}. */
  column: BuildableColumn // storage: fields are encryptable, so stays wide
  table: BuildableTable
}

/** Format for encrypted query/search term return values */
export type EncryptedReturnType =
  | 'eql'
  | 'composite-literal'
  | 'escaped-composite-literal'

export type SearchTerm = {
  value: JsPlaintext
  column: BuildableQueryColumn // query: excludes non-queryable EncryptedField
  table: BuildableTable
  returnType?: EncryptedReturnType
}

/** Encrypted search term result. `eql` return type yields either a storage
 * payload (`Encrypted`, for `ste_vec_term`) or a query-only term
 * (`EncryptedQuery`, for scalar lookups and `ste_vec_selector`); the
 * `composite-literal` return types yield a string. */
export type EncryptedSearchTerm = Encrypted | EncryptedQuery | string

/** Result of encryptQuery (single or batch). `eql` return type yields either a
 * storage payload (`Encrypted`) or a query-only term (`EncryptedQuery`); the
 * `composite-literal` return types yield a string. */
// null elements appear in the batch path when a term has a null/undefined
// value — the operation preserves position so callers can correlate results
// with their input array.
export type EncryptedQueryResult = Encrypted | EncryptedQuery | string | null

// ---------------------------------------------------------------------------
// Model field types (encrypted vs decrypted views)
// ---------------------------------------------------------------------------

export type EncryptedFields<T> = {
  [K in keyof T as NonNullable<T[K]> extends Encrypted ? K : never]: T[K]
}

export type OtherFields<T> = {
  [K in keyof T as NonNullable<T[K]> extends Encrypted ? never : K]: T[K]
}

export type DecryptedFields<T> = {
  [K in keyof T as NonNullable<T[K]> extends Encrypted
    ? K
    : never]: null extends T[K] ? string | null : string
}

/** Model with encrypted fields replaced by plaintext (decrypted) values */
export type Decrypted<T> = OtherFields<T> & DecryptedFields<T>

/**
 * Maps a plaintext model type to its encrypted form using the table schema.
 *
 * Fields whose keys match columns defined in `S` become `Encrypted`;
 * all other fields retain their original types from `T`.
 *
 * When `S` is the widened `EncryptedTableColumn` (e.g. when a user passes an
 * explicit `<User>` type argument without specifying `S`), the type degrades
 * gracefully to `T` — preserving backward compatibility.
 *
 * @typeParam T - The plaintext model type (e.g. `{ id: string; email: string }`)
 * @typeParam S - The table schema column definition, inferred from the `table` argument
 *
 * @example
 * ```typescript
 * type User = { id: string; email: string }
 * // With a schema that defines `email`:
 * type Encrypted = EncryptedFromSchema<User, { email: EncryptedColumn }>
 * // => { id: string; email: Encrypted }
 * ```
 */
export type EncryptedFromSchema<T, S extends EncryptedTableColumn> = {
  [K in keyof T]: [K] extends [keyof S]
    ? [S[K & keyof S]] extends [EncryptedColumn | EncryptedField]
      ? null extends T[K]
        ? Encrypted | null
        : Encrypted
      : T[K]
    : T[K]
}

// ---------------------------------------------------------------------------
// Bulk operations
// ---------------------------------------------------------------------------

// Bulk payloads admit null elements — bulk operations pass them through
// untouched (encrypt(null) -> null, decrypt(null) -> null) so callers can
// process mixed nullable arrays without filtering ahead of time. The
// runtime guards in the operation classes preserve the null in the
// position-stable output.
export type BulkEncryptPayload = Array<{
  id?: string
  plaintext: JsPlaintext | null
}>

export type BulkEncryptedData = Array<{ id?: string; data: Encrypted | null }>
export type BulkDecryptPayload = Array<{ id?: string; data: Encrypted | null }>
export type BulkDecryptedData = Array<DecryptionResult<JsPlaintext | null>>

type DecryptionSuccess<T> = { error?: never; data: T; id?: string }
type DecryptionError<T> = { error: T; id?: string; data?: never }

/**
 * Result type for individual items in bulk decrypt operations.
 * Uses `error`/`data` fields (not `failure`/`data`) since bulk operations
 * can have per-item failures.
 */
export type DecryptionResult<T> = DecryptionSuccess<T> | DecryptionError<T>

// ---------------------------------------------------------------------------
// Query types (for searchable encryption / encryptQuery)
// ---------------------------------------------------------------------------

/**
 * User-facing query type names for encrypting query values.
 *
 * - `'equality'`: Exact match. [Exact Queries](https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption)
 * - `'freeTextSearch'`: Text search. [Match Queries](https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption)
 * - `'orderAndRange'`: Comparison and range. [Range Queries](https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption)
 * - `'steVecSelector'`: JSONPath selector (e.g. `'$.user.email'`)
 * - `'steVecTerm'`: Containment (e.g. `{ role: 'admin' }`)
 * - `'searchableJson'`: Auto-infers selector or term from plaintext type (recommended)
 */
export type QueryTypeName =
  | 'orderAndRange'
  | 'freeTextSearch'
  | 'equality'
  | 'steVecSelector'
  | 'steVecTerm'
  | 'searchableJson'

/** @internal */
export type FfiIndexTypeName = 'ore' | 'match' | 'unique' | 'ste_vec'

export const queryTypes = {
  orderAndRange: 'orderAndRange',
  freeTextSearch: 'freeTextSearch',
  equality: 'equality',
  steVecSelector: 'steVecSelector',
  steVecTerm: 'steVecTerm',
  searchableJson: 'searchableJson',
} as const satisfies Record<string, QueryTypeName>

/** @internal */
export const queryTypeToFfi: Record<QueryTypeName, FfiIndexTypeName> = {
  orderAndRange: 'ore',
  freeTextSearch: 'match',
  equality: 'unique',
  steVecSelector: 'ste_vec',
  steVecTerm: 'ste_vec',
  searchableJson: 'ste_vec',
}

/** @internal */
export const queryTypeToQueryOp: Partial<Record<QueryTypeName, QueryOpName>> = {
  steVecSelector: 'ste_vec_selector',
  steVecTerm: 'ste_vec_term',
}

/** @internal */
export type QueryTermBase = {
  column: BuildableQueryColumn // query: excludes non-queryable EncryptedField
  table: BuildableTable
  queryType?: QueryTypeName
  returnType?: EncryptedReturnType
}

export type EncryptQueryOptions = QueryTermBase

export type ScalarQueryTerm = QueryTermBase & {
  value: JsPlaintext
}
