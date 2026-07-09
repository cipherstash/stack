import type { Result } from '@byteslice/result'
import type {
  AnyV3Table,
  ColumnsOf,
  PlaintextForColumn,
  QueryableColumnsOf,
  QueryTypesForColumn,
  V3DecryptedModel,
  V3EncryptedModel,
  V3ModelInput,
} from '@/eql/v3'
import { DATE_LIKE_CASTS } from '@/eql/v3/columns'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import type { LockContextInput } from '@/identity'
import type {
  BulkDecryptPayload,
  BulkEncryptPayload,
  ClientConfig,
  Encrypted,
  EncryptedReturnType,
  EncryptOptions,
} from '@/types'
import {
  type BulkDecryptOperation,
  type BulkEncryptModelsOperation,
  type BulkEncryptOperation,
  type DecryptOperation,
  Encryption,
  type EncryptionClient,
  type EncryptModelOperation,
  type EncryptOperation,
  type EncryptQueryOperation,
} from './index'

/**
 * A strongly-typed view over an {@link EncryptionClient} for EQL v3 schemas.
 *
 * Every method derives its types from the concrete `table` / `column` builder
 * arguments (which carry their branded types at the call site), so:
 * - `encrypt` / `encryptQuery` pin the plaintext to the column's domain type
 *   (`text → string`, `timestamp → Date`, …);
 * - `encryptQuery` additionally constrains `queryType` to the column's
 *   capabilities and rejects storage-only columns outright;
 * - `encryptModel` / `bulkEncryptModels` validate schema-column fields against
 *   their inferred plaintext type (passthrough fields are untouched) and return
 *   a precise encrypted model;
 * - `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
 *   reconstructing `Date` values from the encrypt-config `cast_as`.
 *
 * @typeParam S - the tuple of registered v3 tables; `table` arguments must be a
 *   member of this tuple.
 */
export interface TypedEncryptionClient<S extends readonly AnyV3Table[]> {
  encrypt<Table extends S[number], Col extends ColumnsOf<Table>>(
    plaintext: PlaintextForColumn<Col>,
    opts: { table: Table; column: Col },
  ): EncryptOperation

  encryptQuery<
    Table extends S[number],
    Col extends QueryableColumnsOf<Table>,
    QT extends QueryTypesForColumn<Col> = QueryTypesForColumn<Col>,
  >(
    plaintext: PlaintextForColumn<Col>,
    opts: {
      table: Table
      column: Col
      queryType?: QT
      returnType?: EncryptedReturnType
    },
  ): EncryptQueryOperation

  encryptModel<Table extends S[number], T extends Record<string, unknown>>(
    input: V3ModelInput<Table, T>,
    table: Table,
  ): EncryptModelOperation<V3EncryptedModel<Table, T>>

  bulkEncryptModels<Table extends S[number], T extends Record<string, unknown>>(
    input: Array<V3ModelInput<Table, T>>,
    table: Table,
  ): BulkEncryptModelsOperation<V3EncryptedModel<Table, T>>

  /**
   * Decrypt a single value. Cannot be strongly typed — a lone ciphertext carries
   * no column identity — so it resolves to the FFI plaintext union unchanged.
   */
  decrypt(encrypted: Encrypted): DecryptOperation

  /**
   * Decrypt a model, returning the precise plaintext shape for `table`. `Date`
   * columns are reconstructed from the encrypt-config `cast_as`.
   *
   * Pass `lockContext` to decrypt identity-bound data — the same context that
   * was supplied at encrypt time must be provided here.
   *
   * Unlike the encrypt operations this returns a plain `Promise<Result<…>>`
   * rather than a chainable operation, because it maps the resolved value.
   */
  decryptModel<Table extends S[number], T extends Record<string, unknown>>(
    input: T,
    table: Table,
    lockContext?: LockContextInput,
  ): Promise<Result<V3DecryptedModel<Table, T>, EncryptionError>>

  bulkDecryptModels<Table extends S[number], T extends Record<string, unknown>>(
    input: Array<T>,
    table: Table,
    lockContext?: LockContextInput,
  ): Promise<Result<Array<V3DecryptedModel<Table, T>>, EncryptionError>>

  // Parity passthroughs — not v3-strengthened, delegated as-is.
  bulkEncrypt(
    plaintexts: BulkEncryptPayload,
    opts: EncryptOptions,
  ): BulkEncryptOperation
  bulkDecrypt(payloads: BulkDecryptPayload): BulkDecryptOperation
  getEncryptConfig(): ReturnType<EncryptionClient['getEncryptConfig']>
}

/**
 * Build a per-row reconstructor of `Date` values from the table's
 * encrypt-config `cast_as`. The FFI returns `JsPlaintext`
 * (string/number/boolean/…) with no `Date`, so those columns arrive as their
 * serialized form and are rebuilt here. Safe (idempotent) if the FFI ever
 * returns `Date` directly: `new Date(date)` is a no-op.
 *
 * A factory rather than a `(row, table)` function so the table config —
 * row-invariant, but non-trivial to build — is derived once per call site,
 * not once per row on the bulk path.
 *
 * NOTE: `bigint` (int8) reconstruction is intentionally absent — int8 domains are
 * omitted from the v3 SDK until the native FFI supports lossless bigint I/O.
 */
function rowReconstructor(
  table: AnyV3Table,
): (row: Record<string, unknown>) => Record<string, unknown> {
  // The decrypted row is keyed by JS property name, but `cast_as` lives on the
  // config keyed by DB name — bridge the two via the table's property→DB map.
  const { columns } = table.build()
  const propToDb = table.buildColumnKeyMap()
  // Only date-like columns need per-row work; resolve them up front.
  const dateProperties = Object.entries(propToDb)
    .filter(([, dbName]) => {
      const castAs = columns[dbName]?.cast_as
      // Date-like casts share one source of truth with the type-level
      // reconstruction (`PlaintextFromKind`) — see `DATE_LIKE_CASTS`.
      return (DATE_LIKE_CASTS as readonly string[]).includes(castAs as string)
    })
    .map(([property]) => property)

  return (row) => {
    const out: Record<string, unknown> = { ...row }
    for (const property of dateProperties) {
      const value = out[property]
      if (value == null) continue
      out[property] = new Date(value as string | number | Date)
    }
    return out
  }
}

/**
 * Wrap an already-built {@link EncryptionClient} in a {@link TypedEncryptionClient}
 * for the given v3 schemas. Zero runtime cost for the encrypt/query paths (the
 * underlying operations are returned unchanged); the decrypt-model paths add a
 * per-column `Date` reconstruction step.
 *
 * The `schemas` are captured with a `const` type parameter so array-literal
 * widening does not collapse per-table inference.
 */
export function typedClient<const S extends readonly AnyV3Table[]>(
  client: EncryptionClient,
  ...schemas: S
): TypedEncryptionClient<S> {
  // Precompute one row reconstructor per schema table at construction. This runs
  // each table's `build()` — which throws on duplicate DB column names — ONCE,
  // here, off the Result-returning decrypt path. `decryptModel`/
  // `bulkDecryptModels` therefore never call `build()` (whose throw would surface
  // as a promise rejection and break their `Promise<Result<…>>` contract) and no
  // longer rebuild the row-invariant config on every call.
  const reconstructors = new Map<
    AnyV3Table,
    (row: Record<string, unknown>) => Record<string, unknown>
  >()
  for (const table of schemas) {
    reconstructors.set(table, rowReconstructor(table))
  }

  // A table not among the schemas this client was initialized with (only
  // reachable by bypassing the `Table extends S[number]` type constraint) has no
  // precomputed reconstructor. Return a Result failure rather than building one
  // inline, which could throw and reject the Result-shaped decrypt promise.
  const unknownTableFailure: { failure: EncryptionError } = {
    failure: {
      type: EncryptionErrorTypes.DecryptionError,
      message:
        '[eql/v3]: decryptModel received a table this client was not initialized with — pass the same table object(s) given to EncryptionV3/typedClient',
    },
  }

  return {
    encrypt: (plaintext, opts) =>
      client.encrypt(plaintext as never, opts as never),
    encryptQuery: (plaintext, opts) =>
      client.encryptQuery(plaintext as never, opts as never),
    encryptModel: (input, table) =>
      client.encryptModel(input as never, table as never) as never,
    bulkEncryptModels: (input, table) =>
      client.bulkEncryptModels(input as never, table as never) as never,
    decrypt: (encrypted) => client.decrypt(encrypted),
    decryptModel: async (input, table, lockContext) => {
      const reconstruct = reconstructors.get(table)
      if (!reconstruct) return unknownTableFailure as never
      const op = client.decryptModel(input as never)
      const result = await (lockContext ? op.withLockContext(lockContext) : op)
      if (result.failure) return result as never
      return { data: reconstruct(result.data) } as never
    },
    bulkDecryptModels: async (input, table, lockContext) => {
      const reconstruct = reconstructors.get(table)
      if (!reconstruct) return unknownTableFailure as never
      const op = client.bulkDecryptModels(input as never)
      const result = await (lockContext ? op.withLockContext(lockContext) : op)
      if (result.failure) return result as never
      return {
        data: result.data.map((row) =>
          reconstruct(row as Record<string, unknown>),
        ),
      } as never
    },
    bulkEncrypt: (plaintexts, opts) => client.bulkEncrypt(plaintexts, opts),
    bulkDecrypt: (payloads) => client.bulkDecrypt(payloads),
    getEncryptConfig: () => client.getEncryptConfig(),
  } satisfies TypedEncryptionClient<S>
}

/**
 * Build a {@link TypedEncryptionClient} for EQL v3 schemas — the strongly-typed
 * counterpart to {@link Encryption}. Mirrors its config, then retypes the client
 * against the provided v3 `schemas`.
 *
 * @example
 * ```typescript
 * import { EncryptionV3, encryptedTable, types } from "@cipherstash/stack/v3"
 *
 * const users = encryptedTable("users", { email: types.TextSearch("email") })
 * const client = await EncryptionV3({ schemas: [users] })
 *
 * await client.encrypt("a@b.com", { table: users, column: users.email })
 * ```
 */
export async function EncryptionV3<
  const S extends readonly AnyV3Table[],
>(config: {
  schemas: S
  config?: ClientConfig
}): Promise<TypedEncryptionClient<S>> {
  const client = await Encryption({
    schemas: config.schemas as unknown as Parameters<
      typeof Encryption
    >[0]['schemas'],
    // Force the v3 EQL wire format. protect-ffi's newClient defaults to
    // eqlVersion 2; a v2-mode client cannot resolve v3 concrete-type columns
    // and fails every encrypt with "Cannot convert undefined or null to
    // object". This is a v3-only invariant, so it overrides any user value.
    config: { ...config.config, eqlVersion: 3 },
  })
  return typedClient(client, ...config.schemas)
}

// Single import surface: re-export the v3 `types` namespace + table API + type
// helpers so `@cipherstash/stack/v3` provides everything needed to author and
// use a schema.
export * from '@/eql/v3'
