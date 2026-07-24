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
  Encrypted,
  EncryptedReturnType,
  EncryptOptions,
  ScalarQueryTerm,
} from '@/types'
import {
  type BatchEncryptQueryOperation,
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
import {
  type AuditableDecryptModelOperation,
  MappedDecryptOperation,
} from './operations/mapped-decrypt'

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

  /**
   * Batch form: encrypt many query terms in one crossing. Mirrors the nominal
   * {@link EncryptionClient} overload — the per-term columns are heterogeneous,
   * so the terms are the base {@link ScalarQueryTerm} rather than a per-column
   * narrowed type. Consumed by the Drizzle `inArray`/`notInArray` operators.
   */
  encryptQuery(terms: readonly ScalarQueryTerm[]): BatchEncryptQueryOperation

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
   * was supplied at encrypt time must be provided here (or chain
   * `.withLockContext()` on the returned operation).
   *
   * Returns a chainable {@link AuditableDecryptModelOperation}: await it for the
   * `Result`, or chain `.audit({ metadata })` / `.withLockContext()` first. The
   * per-row `Date` reconstruction is applied to the successful result.
   */
  decryptModel<Table extends S[number], T extends Record<string, unknown>>(
    input: T,
    table: Table,
    lockContext?: LockContextInput,
  ): AuditableDecryptModelOperation<V3DecryptedModel<Table, T>>

  bulkDecryptModels<Table extends S[number], T extends Record<string, unknown>>(
    input: Array<T>,
    table: Table,
    lockContext?: LockContextInput,
  ): AuditableDecryptModelOperation<Array<V3DecryptedModel<Table, T>>>

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
 * NOTE: only date-like casts need per-row reconstruction. `bigint` (int8)
 * needs none — protect-ffi 0.28 returns a native JS `bigint` on decrypt
 * (and bounds-checks/encodes it on encrypt), so those columns pass through
 * unchanged, exactly like `string`/`number`/`boolean`.
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
  // Keyed by `tableName`, not table object identity: `AnyV3Table` is
  // structurally typed, so a table re-imported from another module (or rebuilt
  // after an HMR reload) satisfies `Table extends S[number]` yet is a different
  // object. Identity keying would fail those valid calls. `tableName` is the
  // semantic identity the FFI encrypt config and `build()` already key on.
  const reconstructors = new Map<
    string,
    (row: Record<string, unknown>) => Record<string, unknown>
  >()
  for (const table of schemas) {
    reconstructors.set(table.tableName, rowReconstructor(table))
  }

  // A table not among the schemas this client was initialized with has no
  // precomputed reconstructor. Return a Result failure rather than building one
  // inline, which could throw and reject the Result-shaped decrypt promise.
  const unknownTableFailure: { failure: EncryptionError } = {
    failure: {
      type: EncryptionErrorTypes.DecryptionError,
      message:
        '[eql/v3]: decryptModel received a table this client was not initialized with — pass a table given to EncryptionV3/typedClient',
    },
  }

  // Pass-through maps for a one-arg (nominal-style) decrypt call, where `table`
  // is absent: decrypt WITHOUT date reconstruction, exactly as the nominal
  // `EncryptionClient` does. This client is now what `Encryption` returns for a
  // v3 schema set, so a consumer typed against the nominal overload (e.g.
  // stack-supabase's query builder, which casts to it) can call `decryptModel(x)`
  // / `bulkDecryptModels(xs)` with no table. Degrade gracefully instead of
  // dereferencing `undefined.tableName`.
  const passthroughRow = (row: Record<string, unknown>) => row
  const passthroughRows = (rows: Array<Record<string, unknown>>) => rows

  // Overloaded so the implementation is checked against BOTH forms directly —
  // no whole-value cast. The two public signatures mirror the interface member;
  // the hidden implementation signature is broad and forwards to the nominal
  // client (which routes to the batch operation when no `opts` are supplied).
  // Only the forwarded args are `as never`, exactly as the sibling wrappers
  // below: one forwarding body cannot re-derive the nominal client's per-column
  // signatures.
  function encryptQuery<
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
  function encryptQuery(
    terms: readonly ScalarQueryTerm[],
  ): BatchEncryptQueryOperation
  function encryptQuery(
    plaintextOrTerms: unknown,
    opts?: unknown,
  ): EncryptQueryOperation | BatchEncryptQueryOperation {
    return client.encryptQuery(plaintextOrTerms as never, opts as never)
  }

  return {
    encrypt: (plaintext, opts) =>
      client.encrypt(plaintext as never, opts as never),
    encryptQuery,
    encryptModel: (input, table) =>
      client.encryptModel(input as never, table as never) as never,
    bulkEncryptModels: (input, table) =>
      client.bulkEncryptModels(input as never, table as never) as never,
    decrypt: (encrypted) => client.decrypt(encrypted),
    decryptModel: (input, table, lockContext) => {
      // `table` is absent on a nominal-style one-arg call (see `passthroughRow`).
      // Given a table: reconstruct dates from its cast_as, or — if it was never
      // registered — leave `map` undefined so the mapped op resolves to
      // `unknownTableFailure` on execute.
      const maybeTable = table as AnyV3Table | undefined
      const reconstruct = maybeTable
        ? reconstructors.get(maybeTable.tableName)
        : passthroughRow
      const op = client.decryptModel(input as never)
      const base = lockContext ? op.withLockContext(lockContext) : op
      return new MappedDecryptOperation(
        base,
        reconstruct,
        unknownTableFailure,
      ) as never
    },
    bulkDecryptModels: (input, table, lockContext) => {
      const maybeTable = table as AnyV3Table | undefined
      const op = client.bulkDecryptModels(input as never)
      const base = lockContext ? op.withLockContext(lockContext) : op
      // No table → pass rows through (nominal behaviour). Registered table →
      // reconstruct each row. Unregistered table → `undefined` map →
      // `unknownTableFailure` on execute.
      let mapRows:
        | ((
            rows: Array<Record<string, unknown>>,
          ) => Array<Record<string, unknown>>)
        | undefined
      if (!maybeTable) {
        mapRows = passthroughRows
      } else {
        const reconstruct = reconstructors.get(maybeTable.tableName)
        mapRows = reconstruct ? (rows) => rows.map(reconstruct) : undefined
      }
      return new MappedDecryptOperation(
        base,
        mapRows,
        unknownTableFailure,
      ) as never
    },
    bulkEncrypt: (plaintexts, opts) => client.bulkEncrypt(plaintexts, opts),
    bulkDecrypt: (payloads) => client.bulkDecrypt(payloads),
    getEncryptConfig: () => client.getEncryptConfig(),
  } satisfies TypedEncryptionClient<S>
}

/**
 * @deprecated Use {@link Encryption} instead — it is now overloaded so an array
 * of concrete EQL v3 tables yields the same strongly-typed client this used to.
 * `EncryptionV3` is a type-identical alias of `Encryption`, retained for
 * backwards compatibility, and will be removed in a future release.
 *
 * @example
 * ```typescript
 * import { Encryption, encryptedTable, types } from "@cipherstash/stack/v3"
 *
 * const users = encryptedTable("users", { email: types.TextSearch("email") })
 * const client = await Encryption({ schemas: [users] })
 *
 * await client.encrypt("a@b.com", { table: users, column: users.email })
 * ```
 */
export const EncryptionV3 = Encryption

// Single import surface: re-export the v3 `types` namespace + table API + type
// helpers so `@cipherstash/stack/v3` provides everything needed to author and
// use a schema.
export * from '@/eql/v3'
// `Encryption` comes along for the same reason — it is the current name for
// what `EncryptionV3` aliases, so authoring a v3 schema and building its
// client should not need a second import specifier.
export { Encryption }
