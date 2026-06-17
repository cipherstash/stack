import type {
  Encrypted as CipherStashEncrypted,
  EncryptedQuery as CipherStashEncryptedQuery,
  JsPlaintext,
  newClient,
  QueryOpName,
} from '@cipherstash/protect-ffi'
import type {
  ProtectColumn,
  ProtectTable,
  ProtectTableColumn,
  ProtectValue,
} from '@cipherstash/schema'

/**
 * Type to represent the client object
 */
export type Client = Awaited<ReturnType<typeof newClient>> | undefined

/**
 * Type to represent an encrypted payload stored in the database. Always carries
 * a ciphertext — scalar payloads at the root (`c`), SteVec payloads at
 * `sv[0].c`. For search-term payloads returned by `encryptQuery`, see
 * {@link EncryptedQuery}.
 */
export type Encrypted = CipherStashEncrypted | null

/**
 * Type to represent an encrypted query term (search needle) returned by
 * `encryptQuery` / `encryptQueryBulk` for scalar (`unique` / `match` / `ore`)
 * lookups and `ste_vec_selector` JSON path queries. Carries no ciphertext — it
 * is matched against stored values, never decrypted. JSON containment queries
 * (`ste_vec_term`) return a storage-shaped {@link Encrypted} payload instead.
 */
export type EncryptedQuery = CipherStashEncryptedQuery | null

/**
 * Represents an encrypted payload in the database
 * @deprecated Use `Encrypted` instead
 */
export type EncryptedPayload = Encrypted | null

/**
 * Represents an encrypted data object in the database
 * @deprecated Use `Encrypted` instead
 */
export type EncryptedData = Encrypted | null

/**
 * Represents a value that will be encrypted and used in a search
 */
export type SearchTerm = {
  value: JsPlaintext
  column: ProtectColumn
  table: ProtectTable<ProtectTableColumn>
  returnType?: 'eql' | 'composite-literal' | 'escaped-composite-literal'
}

export type KeysetIdentifier =
  | {
      name: string
    }
  | {
      id: string
    }

/**
 * The return type of the search term based on the return type specified in the `SearchTerm` type.
 * - `eql` → an `Encrypted` storage payload (for `ste_vec_term` containment) or an
 *   {@link EncryptedQuery} term (for scalar lookups and `ste_vec_selector` queries).
 * - `composite-literal` → `string` where the value is a composite literal.
 * - `escaped-composite-literal` → `string` where the value is an escaped composite literal.
 */
export type EncryptedSearchTerm = Encrypted | EncryptedQuery | string

/**
 * Result type for encryptQuery batch operations.
 * Can be an `Encrypted` storage payload (e.g. for `ste_vec_term`), an
 * {@link EncryptedQuery} term (for scalar lookups and `ste_vec_selector`),
 * a `string` (for composite-literal formats), or `null` (for null inputs).
 */
export type EncryptedQueryResult = Encrypted | EncryptedQuery | string | null

/**
 * Represents a payload to be encrypted using the `encrypt` function
 */
export type EncryptPayload = JsPlaintext | null

/**
 * Represents the options for encrypting a payload using the `encrypt` function
 */
export type EncryptOptions = {
  column: ProtectColumn | ProtectValue
  table: ProtectTable<ProtectTableColumn>
}

/**
 * Type to identify encrypted fields in a model
 */
export type EncryptedFields<T> = {
  [K in keyof T as T[K] extends Encrypted ? K : never]: T[K]
}

/**
 * Type to identify non-encrypted fields in a model
 */
export type OtherFields<T> = {
  [K in keyof T as T[K] extends Encrypted ? never : K]: T[K]
}

/**
 * Type to represent decrypted fields in a model
 */
export type DecryptedFields<T> = {
  [K in keyof T as T[K] extends Encrypted ? K : never]: string
}

/**
 * Represents a model with plaintext (decrypted) values instead of the EQL/JSONB types
 */
export type Decrypted<T> = OtherFields<T> & DecryptedFields<T>

/**
 * Types for bulk encryption and decryption operations.
 */
export type BulkEncryptPayload = Array<{
  id?: string
  plaintext: JsPlaintext | null
}>

export type BulkEncryptedData = Array<{ id?: string; data: Encrypted }>
export type BulkDecryptPayload = Array<{ id?: string; data: Encrypted }>
export type BulkDecryptedData = Array<DecryptionResult<JsPlaintext | null>>

type DecryptionSuccess<T> = {
  error?: never
  data: T
  id?: string
}

type DecryptionError<T> = {
  error: T
  id?: string
  data?: never
}

export type DecryptionResult<T> = DecryptionSuccess<T> | DecryptionError<T>

/**
 * User-facing query type names for encrypting query values.
 *
 * - `'equality'`: For exact match queries. {@link https://cipherstash.com/docs/platform/searchable-encryption/supported-queries/exact | Exact Queries}
 * - `'freeTextSearch'`: For text search queries. {@link https://cipherstash.com/docs/platform/searchable-encryption/supported-queries/match | Match Queries}
 * - `'orderAndRange'`: For comparison and range queries. {@link https://cipherstash.com/docs/platform/searchable-encryption/supported-queries/range | Range Queries}
 * - `'steVecSelector'`: For JSONPath selector queries (e.g., '$.user.email')
 * - `'steVecTerm'`: For containment queries (e.g., { role: 'admin' })
 * - `'searchableJson'`: Auto-infers selector or term based on plaintext type (recommended)
 *   - String values → ste_vec_selector (JSONPath queries)
 *   - Object/Array/Number/Boolean → ste_vec_term (containment queries)
 *
 * Note: For columns with an ste_vec index, `'searchableJson'` behaves identically to omitting
 * `queryType` entirely - both auto-infer the query operation from the plaintext type. Using
 * `'searchableJson'` explicitly is useful for code clarity and self-documenting intent.
 */
export type QueryTypeName =
  | 'orderAndRange'
  | 'freeTextSearch'
  | 'equality'
  | 'steVecSelector'
  | 'steVecTerm'
  | 'searchableJson'

/**
 * Internal FFI index type names.
 * @internal
 */
export type FfiIndexTypeName = 'ore' | 'match' | 'unique' | 'ste_vec'

/**
 * Query type constants for use with encryptQuery().
 */
export const queryTypes = {
  orderAndRange: 'orderAndRange',
  freeTextSearch: 'freeTextSearch',
  equality: 'equality',
  steVecSelector: 'steVecSelector',
  steVecTerm: 'steVecTerm',
  searchableJson: 'searchableJson',
} as const satisfies Record<string, QueryTypeName>

/**
 * Maps user-friendly query type names to FFI index type names.
 * @internal
 */
export const queryTypeToFfi: Record<QueryTypeName, FfiIndexTypeName> = {
  orderAndRange: 'ore',
  freeTextSearch: 'match',
  equality: 'unique',
  steVecSelector: 'ste_vec',
  steVecTerm: 'ste_vec',
  searchableJson: 'ste_vec',
}

/**
 * Maps query type names to FFI query operation names.
 * Returns undefined for query types that don't need a specific queryOp.
 * @internal
 */
export const queryTypeToQueryOp: Partial<Record<QueryTypeName, QueryOpName>> = {
  steVecSelector: 'ste_vec_selector',
  steVecTerm: 'ste_vec_term',
}

/**
 * Base type for query term options shared between single and bulk operations.
 * @internal
 */
export type QueryTermBase = {
  column: ProtectColumn
  table: ProtectTable<ProtectTableColumn>
  queryType?: QueryTypeName // Optional - auto-infers if omitted
  /**
   * The format for the returned encrypted value:
   * - `'eql'` (default) - Returns raw Encrypted object
   * - `'composite-literal'` - Returns PostgreSQL composite literal format `("json")`
   * - `'escaped-composite-literal'` - Returns escaped format `"(\"json\")"`
   */
  returnType?: 'eql' | 'composite-literal' | 'escaped-composite-literal'
}

/**
 * Options for encrypting a single query term.
 */
export type EncryptQueryOptions = QueryTermBase

/**
 * Individual query term for bulk operations.
 */
export type ScalarQueryTerm = QueryTermBase & {
  value: JsPlaintext | null
}
