import type {
  AuthStrategy,
  Encrypted as CipherStashEncrypted,
  EncryptedPayload as CipherStashEncryptedPayload,
  EncryptedQuery as CipherStashEncryptedQuery,
  EncryptedV3Query as CipherStashEncryptedV3Query,
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
 * (service-to-service / CI). When supplied to {@link ClientConfig.authStrategy},
 * `getToken()` is invoked on every ZeroKMS request, taking precedence over
 * the default `auto` strategy.
 *
 * @see ClientConfig.authStrategy
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
 * carries a ciphertext. Covers BOTH wire formats: the EQL v2.3 payloads
 * (`k: "ct"` / `k: "sv"`) and the EQL v3 payloads (flat `{v: 3, i, c, …}`
 * scalars and `{v: 3, k: "sv", i, sv}` SteVec documents). Which format
 * `encrypt` produces is selected by the client's
 * {@link ClientConfig.eqlVersion}; `decrypt` accepts both regardless.
 * v3 scalars carry no `k` discriminator, so narrow with `'k' in payload`
 * before reading it. See also `EncryptedValue` for branded nominal typing,
 * and {@link EncryptedQuery} for the search-term shape returned by
 * `encryptQuery`. */
export type Encrypted = CipherStashEncryptedPayload

/** Structural type representing an encrypted query term (search needle)
 * returned by `encryptQuery` / `encryptQueryBulk` for scalar
 * (`unique` / `match` / `ore`) lookups and `ste_vec_selector` JSON path
 * queries, plus — under `eqlVersion: 3` — the `eql_v3.jsonb_query`
 * containment needle. Carries no ciphertext — matched against stored
 * values, never decrypted. v2 JSON containment queries (`ste_vec_term`)
 * return a storage-shaped {@link Encrypted} payload instead. */
export type EncryptedQuery =
  | CipherStashEncryptedQuery
  | CipherStashEncryptedV3Query

/**
 * Plaintext values the SDK accepts for encryption.
 *
 * Widens the FFI's `JsPlaintext` (`string | number | boolean |
 * Record<string, unknown> | JsPlaintext[]`) with `Date` and `bigint`. `Date`
 * is a supported cast target that is omitted from the FFI's `JsPlaintext` INPUT
 * union, but it serializes at the boundary via `toJSON` (ISO string), so it is
 * accepted on the way in.
 *
 * `bigint` is the plaintext for the v3 int8/bigint domains (see `eql/v3`),
 * which always decrypt to a JS `bigint`. protect-ffi 0.28 marshals a native
 * `bigint` across the Neon boundary losslessly. i64 bounds
 * (`-2^63 … 2^63 - 1`) are enforced at the protect-ffi boundary, not here —
 * out-of-range values surface as encryption errors from the FFI.
 *
 * When the upstream FFI `JsPlaintext` includes `Date` and `bigint`, both extra
 * arms can collapse back into `JsPlaintext`.
 */
export type Plaintext = JsPlaintext | Date | bigint

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
   * Keysets are created and managed in the
   * [dashboard](https://dashboard.cipherstash.com/workspaces/_/keysets); omit to
   * use the workspace's default keyset. A client is bound to one keyset for its
   * lifetime, so use one client per tenant.
   *
   * @see {@link Encryption} for the full keysets walkthrough.
   */
  keyset?: KeysetIdentifier

  /**
   * An optional authentication strategy for ZeroKMS requests, from
   * `@cipherstash/auth` (re-exported by `@cipherstash/stack`). When provided,
   * its `getToken()` is invoked on every ZeroKMS request and takes precedence
   * over the default `auto` strategy (the `clientKey` is still required for
   * encryption). Use:
   *
   * - `OidcFederationStrategy` for per-user, identity-bound encryption —
   *   federates an end user's OIDC JWT into a CTS service token, so requests
   *   authenticate as that user. Pair with `.withLockContext({ identityClaim })`
   *   to bind the data key to a claim. This replaces the older
   *   `LockContext.identify()` ceremony.
   * - `AccessKeyStrategy` for service-to-service / CI, or any custom
   *   `{ getToken() }` object for bespoke token acquisition / caching.
   *
   * Leave unset to use the default `auto` strategy, which reads credentials
   * from the `CS_*` environment variables and falls back to the local dev
   * profile created by `npx stash auth login`.
   *
   * @see {@link AuthStrategy}
   * @see {@link Encryption} for a full walkthrough of the authentication options.
   */
  authStrategy?: AuthStrategy

  /**
   * @deprecated Renamed to {@link ClientConfig.authStrategy}. Still honoured for
   * backwards compatibility — passing it logs a deprecation warning at runtime —
   * but it will be removed in a future release. Set `authStrategy` instead.
   */
  strategy?: AuthStrategy

  /**
   * The EQL wire version the client emits — one FFI client always emits
   * exactly one wire format.
   *
   * - `2` (the protect-ffi default): payloads target the
   *   `eql_v2_encrypted` column type.
   * - `3`: payloads target the per-capability `eql_v3` domains
   *   (`eql_v3.text_eq`, `eql_v3.integer_ord_ore`, `eql_v3.json`, …),
   *   derived from each column's `cast_as` and indexes.
   *
   * When omitted, {@link Encryption} auto-detects from the schema set:
   * EQL v3 tables (from `@cipherstash/stack/v3`, marked by
   * `buildColumnKeyMap()`) select `3`; v2 tables leave the FFI default
   * (`2`) untouched. Mixing v2 and v3 tables in one client is an error —
   * split them across two clients instead.
   *
   * `decrypt` accepts BOTH formats regardless of this setting, so v2 and
   * v3 data can coexist during a migration.
   *
   * v3 limitation (protect-ffi 0.27): `encryptQuery` supports only JSON
   * containment queries — scalar-index and selector queries throw
   * `EQL_V3_QUERY_UNSUPPORTED` until a v3 scalar query wire shape exists.
   */
  eqlVersion?: 2 | 3
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
export interface BuildableV3QueryableColumn extends BuildableColumn {
  getEqlType(): string
  getQueryCapabilities(): {
    equality: boolean
    orderAndRange: boolean
    freeTextSearch: boolean
  }
  isQueryable(): true
}

export type BuildableQueryColumn = EncryptedColumn | BuildableV3QueryableColumn

/** Structural contract for a table builder the client can consume. Satisfied by
 *  v2 and v3 `EncryptedTable` alike. */
export interface BuildableTable {
  tableName: string
  build(): { tableName: string; columns: Record<string, ColumnSchema> }
  /**
   * Optional map from a model field's JS property name to its encrypt-config
   * column name (the DB name). Present when the two can differ — v3 tables key
   * their config by DB name (`column.getName()`) while models are written with
   * JS property keys, so the model path must match by property but address the
   * FFI/config by DB name.
   *
   * Absent on v2 tables, whose `build()` already keys columns by the JS property
   * name; the model path then matches and addresses by that same key.
   */
  buildColumnKeyMap?(): Record<string, string>
}

export type EncryptionClientConfig = {
  schemas: AtLeastOneCsTable<BuildableTable>
  config?: ClientConfig
}

/**
 * The literal column map of a buildable table, read from its type-level
 * `_columnType` brand. Both v2 and v3 `EncryptedTable` carry this brand, so this
 * recovers the literal column keys structurally.
 *
 * This deliberately uses the `_columnType` brand rather than `build().columns`:
 * `BuildableTable.build()` is typed to return `Record<string, ColumnSchema>`,
 * which erases the literal keys and would mark EVERY model field as encrypted.
 *
 * The fallbacks resolve to `Record<never, never>` (a no-key type), NOT `never`:
 * a value typed as the bare structural `BuildableTable` carries no `_columnType`
 * brand, and `keyof never` is `string | number | symbol` — which would wrongly
 * mark EVERY model field as encrypted. `keyof Record<never, never>` is `never`,
 * so `EncryptedFromBuildableTable` degrades gracefully to the model unchanged.
 */
export type BuildableTableColumns<T extends BuildableTable> = T extends {
  readonly _columnType: infer C
}
  ? C extends Record<string, unknown>
    ? C
    : Record<never, never>
  : Record<never, never>

/**
 * Maps a plaintext model type to its encrypted form using a buildable table.
 *
 * Fields whose keys match a column defined in `Table` (via its `_columnType`
 * brand) become `Encrypted` (`Encrypted | null` when the source field is
 * nullable); all other fields retain their original types from `T`. Works for
 * both v2 and v3 tables. See {@link EncryptedFromSchema} for the v2-specific
 * variant retained for backward compatibility.
 */
export type EncryptedFromBuildableTable<T, Table extends BuildableTable> = {
  [K in keyof T]: [K] extends [keyof BuildableTableColumns<Table>]
    ? null extends T[K]
      ? Encrypted | null
      : Encrypted
    : T[K]
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
  value: Plaintext
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
  plaintext: Plaintext | null
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
  value: Plaintext
}
