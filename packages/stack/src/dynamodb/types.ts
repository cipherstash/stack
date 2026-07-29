import type { ProtectErrorCode } from '@cipherstash/protect-ffi'
import type { EncryptionClient } from '@/encryption/client-v3'
import type {
  AnyV3Table,
  EncryptedTable as EncryptedV3Table,
  InferPlaintext,
  PlaintextForColumn,
  QueryTypesForColumn,
  V3ModelInput,
} from '@/eql/v3'
import type { ciphertextAttrSuffix, searchTermAttrSuffix } from './helpers'
import type { BulkDecryptModelsOperation } from './operations/bulk-decrypt-models'
import type { BulkEncryptModelsOperation } from './operations/bulk-encrypt-models'
import type { DecryptModelOperation } from './operations/decrypt-model'
import type { EncryptModelOperation } from './operations/encrypt-model'

/** An EQL v3 table accepted by every adapter operation. */
export type AnyEncryptedTable = AnyV3Table

export type DynamoDBReadOptions = {
  /** Wire generation of the payload before DynamoDB stripped its envelope. */
  storedEqlVersion?: 2 | 3
}

/**
 * The client capability this adapter consumes, declared structurally so it is
 * satisfied by {@link EncryptionClient} and by the WASM client.
 * Mirrors the approach the Drizzle v3 operators take for the same reason: a
 * nominal `EncryptionClient<S>` parameter would reject a client built for
 * a narrower schema tuple.
 *
 * Both NATIVE clients return a chainable operation on every path — the nominal
 * client's `DecryptModelOperation` and the typed wrapper's
 * `MappedDecryptOperation` each carry `.audit()` (the typed wrapper also takes
 * the table as a second argument). The operation classes handle both; see
 * `DecryptModelOperation` and `resolveDecryptResult`.
 *
 * The wasm-inline client does not, on EITHER path: its encrypt and decrypt are
 * plain `async` methods returning a bare `Promise<WasmResult>`, so audit
 * metadata is dropped (observably — `resolveDecryptResult` and
 * `resolveEncryptResult` log it). Chaining `.audit()` unconditionally is
 * therefore a bug, not just a lost audit record; the encrypt path made exactly
 * that mistake and failed every v3 write on this entry (#788 review follow-up).
 *
 * Its EQL v2 READ path is supported, however. The legacy read reconstructs the
 * v2 envelope around the current v3 table and forwards that table like any
 * other read, so nothing on this entry needs a v2 schema — which is just as
 * well, since its `Encryption()` rejects one.
 */
export type DynamoDBEncryptionClient = {
  encryptModel(input: never, table: never): unknown
  bulkEncryptModels(input: never, table: never): unknown
  decryptModel(input: never, table: never): unknown
  bulkDecryptModels(input: never, table: never): unknown
}

/**
 * @internal Callable view of {@link DynamoDBEncryptionClient}.
 *
 * The public type declares `never` operands so both client shapes satisfy it
 * without a cast; a callable signature cannot be written that both the generic
 * native `EncryptionClient` and the WASM client methods satisfy. The operation
 * classes therefore cast to this shape at the call site
 * — the same split the Drizzle v3 operators use.
 *
 * The returns are intentionally untyped on ALL FOUR members. The clients
 * disagree about what an operation even is: the native client returns a
 * chainable `EncryptModelOperation` / `DecryptModelOperation`, adapters can
 * return a `MappedDecryptOperation`, and the wasm-inline client returns a bare
 * `Promise<WasmResult>` with no `.audit()` anywhere on it.
 *
 * Declaring a chainable shape here asserts an `.audit()` that the wasm entry
 * does not have, and that assertion was not academic — it is exactly what let
 * the write path chain `.audit()` unconditionally and fail EVERY EQL v3 write on
 * that entry (#788 review follow-up). `unknown` forces each call site through
 * `resolveEncryptResult` / `resolveDecryptResult`, which normalise all three
 * shapes and fail closed on anything else.
 */
export type CallableEncryptionClient = {
  encryptModel(
    input: Record<string, unknown>,
    table: AnyEncryptedTable,
  ): unknown
  bulkEncryptModels(
    input: Record<string, unknown>[],
    table: AnyEncryptedTable,
  ): unknown
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
   * The client returned by `Encryption(...)` for this table.
   */
  encryptionClient:
    | EncryptionClient<readonly AnyV3Table[]>
    | DynamoDBEncryptionClient
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

// ---------------------------------------------------------------------------
// The DynamoDB storage split, at the type level
// ---------------------------------------------------------------------------

/** The `__source` / `__hmac` suffixes, read off the runtime constants so the
 * types cannot drift from the mapping in `helpers.ts`. */
type CiphertextSuffix = typeof ciphertextAttrSuffix
type SearchTermSuffix = typeof searchTermAttrSuffix

/** The column map a v3 table was declared with. */
type V3Columns<Table extends AnyV3Table> =
  Table extends EncryptedV3Table<infer C> ? C : never

/**
 * What `toEncryptedDynamoItem` writes into `<attr>__source` for a column: for a
 * JSON document, the SteVec entries plus the per-document KeyHeader `h`
 * (`{ h, sv }`) — protect-ffi 0.30 decrypt requires `h`; for every scalar, the
 * base64 ciphertext `c`.
 */
type SourceAttribute<C> =
  'searchableJson' extends QueryTypesForColumn<C>
    ? { h: unknown; sv: unknown[] }
    : string

/**
 * Does this column mint the `hm` term that becomes `<attr>__hmac`?
 *
 * Mirrors `indexesForCapabilities` (eql/v3/columns.ts) exactly: `hm` comes from
 * the `unique` index, which is emitted when a domain is equality-capable AND is
 * either not an ordering domain or is text (text equality is always HMAC-based,
 * numeric/date ordering domains answer equality via their ordering term and
 * emit no `unique`). A JSON document keeps its terms inside `sv`, so it has no
 * separate search-term attribute.
 *
 * Derived from the public `QueryTypesForColumn` / `PlaintextForColumn` rather
 * than the internal domain literal, so it stays inside the v3 barrel's API.
 */
type HasSearchTerm<C> =
  'searchableJson' extends QueryTypesForColumn<C>
    ? false
    : 'equality' extends QueryTypesForColumn<C>
      ? 'orderAndRange' extends QueryTypesForColumn<C>
        ? [PlaintextForColumn<C>] extends [string]
          ? true
          : false
        : true
      : false

/** Flatten an intersection into a single object type for readable errors. */
type Simplify<T> = { [K in keyof T]: T[K] }

/**
 * The DynamoDB attribute map `encryptModel` actually returns for a v3 table.
 *
 * A declared column `email` does NOT survive as `email`: the adapter deletes it
 * and writes `email__source` (plus `email__hmac` for equality domains). Typing
 * the result as the input model is a lie that type-checks `result.data.email`
 * (always `undefined` at runtime) and rejects `result.data.email__source` (the
 * value you actually want).
 *
 * Keys that name no column pass through untouched — partition/sort keys, GSI
 * attributes, anything else on the item.
 *
 * LIMITATION: a v3 column declared under a dotted path (`'profile.ssn'`) is
 * split *inside* the nested `profile` map at runtime. The model key is
 * `profile`, not `profile.ssn`, so it passes through here unchanged and the
 * nested split is not modelled.
 *
 * LIMITATION: values inside an ARRAY are not descended into — the write path
 * skips arrays, so a payload in a list is stored whole rather than split into
 * `<attr>__source`/`__hmac`. It still decrypts on read, but this mapped type
 * describes it as its plaintext input shape, not a split. Documented in the
 * DynamoDB skill's limitations.
 */
export type EncryptedAttributes<Table extends AnyV3Table, T> = Simplify<
  {
    [K in keyof T as K extends keyof V3Columns<Table> & string
      ? `${K}${CiphertextSuffix}`
      : K]: K extends keyof V3Columns<Table>
      ? SourceAttribute<V3Columns<Table>[K]>
      : T[K]
  } & {
    // Optional: the term is only written when the encrypted value produced one,
    // so a null/absent field leaves the attribute off the item entirely.
    [K in keyof T as K extends keyof V3Columns<Table> & string
      ? HasSearchTerm<V3Columns<Table>[K]> extends true
        ? `${K}${SearchTermSuffix}`
        : never
      : never]?: string
  }
>

/**
 * The inverse of {@link EncryptedAttributes}: the plaintext model
 * `decryptModel` returns for an item read back out of DynamoDB.
 *
 * `<col>__source` folds back to `col` with the column's plaintext type,
 * `<col>__hmac` is dropped (it is a query term, not data), and every other
 * attribute passes through. Declared this way — rather than taking the
 * plaintext model as the input parameter — so `T` is inferred from the argument
 * a caller actually has: the stored attribute map.
 */
export type DecryptedAttributes<Table extends AnyV3Table, T> = Simplify<{
  [K in keyof T as K extends `${infer Base}${SearchTermSuffix}`
    ? Base extends keyof V3Columns<Table>
      ? never
      : K
    : K extends `${infer Base}${CiphertextSuffix}`
      ? Base extends keyof V3Columns<Table>
        ? Base
        : K
      : K]: K extends `${infer Base}${CiphertextSuffix}`
    ? Base extends keyof InferPlaintext<Table>
      ? InferPlaintext<Table>[Base]
      : T[K]
    : T[K]
}>

export interface EncryptedDynamoDBInstance {
  /**
   * EQL v3: the input model is checked against the table's column types, and
   * the result is the {@link EncryptedAttributes} storage split.
   */
  encryptModel<Table extends AnyV3Table, T extends Record<string, unknown>>(
    item: V3ModelInput<Table, T>,
    table: Table,
  ): EncryptModelOperation<EncryptedAttributes<Table, T>>

  /** EQL v3. See {@link EncryptedDynamoDBInstance.encryptModel}. */
  bulkEncryptModels<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(
    items: Array<V3ModelInput<Table, T>>,
    table: Table,
  ): BulkEncryptModelsOperation<EncryptedAttributes<Table, T>>

  /**
   * EQL v3: `item` is the stored attribute map (`<col>__source` /
   * `<col>__hmac`), and the result is the {@link DecryptedAttributes} plaintext
   * model it folds back to.
   */
  decryptModel<Table extends AnyV3Table, T extends Record<string, unknown>>(
    item: T,
    table: Table,
    options?: DynamoDBReadOptions,
  ): DecryptModelOperation<DecryptedAttributes<Table, T>>

  /** EQL v3. See {@link EncryptedDynamoDBInstance.decryptModel}. */
  bulkDecryptModels<
    Table extends AnyV3Table,
    T extends Record<string, unknown>,
  >(
    items: T[],
    table: Table,
    options?: DynamoDBReadOptions,
  ): BulkDecryptModelsOperation<DecryptedAttributes<Table, T>>
}
