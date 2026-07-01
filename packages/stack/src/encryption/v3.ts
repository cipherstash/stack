import type { Result } from '@byteslice/result'
import type { EncryptionError } from '@/errors'
import type {
  AnyV3Table,
  ColumnsOf,
  PlaintextForColumn,
  QueryableColumnsOf,
  QueryTypesForColumn,
  V3DecryptedModel,
  V3EncryptedModel,
  V3ModelInput,
} from '@/schema/v3'
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
 *   (`text → string`, `int8 → bigint`, `timestamptz → Date`, …);
 * - `encryptQuery` additionally constrains `queryType` to the column's
 *   capabilities and rejects storage-only columns outright;
 * - `encryptModel` / `bulkEncryptModels` validate schema-column fields against
 *   their inferred plaintext type (passthrough fields are untouched) and return
 *   a precise encrypted model;
 * - `decryptModel` / `bulkDecryptModels` return the precise plaintext model,
 *   reconstructing `Date` / `bigint` values from the encrypt-config `cast_as`.
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
   * and `bigint` columns are reconstructed from the encrypt-config `cast_as`.
   *
   * Unlike the encrypt operations this returns a plain `Promise<Result<…>>`
   * rather than a chainable operation, because it maps the resolved value.
   */
  decryptModel<Table extends S[number], T extends Record<string, unknown>>(
    input: T,
    table: Table,
  ): Promise<Result<V3DecryptedModel<Table, T>, EncryptionError>>

  bulkDecryptModels<Table extends S[number], T extends Record<string, unknown>>(
    input: Array<T>,
    table: Table,
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
 * Reconstruct `Date` / `bigint` values on a decrypted row from the table's
 * encrypt-config `cast_as`. The FFI returns `JsPlaintext` (string/number/boolean/
 * …) with no `Date` / `bigint`, so those columns arrive as their serialized form
 * and are rebuilt here. Safe (idempotent) if the FFI ever returns `Date` /
 * `bigint` directly: `new Date(date)` / `BigInt(bigint)` are no-ops.
 */
function reconstructRow(
  row: Record<string, unknown>,
  table: AnyV3Table,
): Record<string, unknown> {
  const { columns } = table.build()
  const out: Record<string, unknown> = { ...row }
  for (const [key, schema] of Object.entries(columns)) {
    const value = out[key]
    if (value == null) continue
    if (schema.cast_as === 'date') {
      out[key] = new Date(value as string | number | Date)
    } else if (schema.cast_as === 'bigint') {
      out[key] = BigInt(value as string | number | bigint)
    }
  }
  return out
}

/**
 * Wrap an already-built {@link EncryptionClient} in a {@link TypedEncryptionClient}
 * for the given v3 schemas. Zero runtime cost for the encrypt/query paths (the
 * underlying operations are returned unchanged); the decrypt-model paths add a
 * per-column `Date` / `bigint` reconstruction step.
 *
 * The `schemas` are captured with a `const` type parameter so array-literal
 * widening does not collapse per-table inference.
 */
export function typedClient<const S extends readonly AnyV3Table[]>(
  client: EncryptionClient,
  ..._schemas: S
): TypedEncryptionClient<S> {
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
    decryptModel: async (input, table) => {
      const result = await client.decryptModel(input as never)
      if (result.failure) return result as never
      return { data: reconstructRow(result.data, table) } as never
    },
    bulkDecryptModels: async (input, table) => {
      const result = await client.bulkDecryptModels(input as never)
      if (result.failure) return result as never
      return {
        data: result.data.map((row) =>
          reconstructRow(row as Record<string, unknown>, table),
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
 * import { EncryptionV3, encryptedTable, encryptedTextSearchColumn } from "@cipherstash/stack/v3"
 *
 * const users = encryptedTable("users", { email: encryptedTextSearchColumn("email") })
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
    config: config.config,
  })
  return typedClient(client, ...config.schemas)
}

// Single import surface: re-export the v3 builders + type helpers so
// `@cipherstash/stack/v3` provides everything needed to author and use a schema.
export * from '@/schema/v3'
