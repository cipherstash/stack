import type { ColumnSchema, EncryptConfig } from '@/schema'
import type { Encrypted } from '@/types'
import type {
  EncryptedV3TableColumn,
  PlaintextForColumn,
  QueryTypesForColumn,
} from './columns'

interface TableDefinition {
  tableName: string
  columns: Record<string, ColumnSchema>
}

/**
 * A v3 encrypted table. Mirrors the v2 `EncryptedTable` but only accepts v3
 * column builders. Emits the same `{ tableName, columns }` definition shape.
 */
export class EncryptedTable<T extends EncryptedV3TableColumn> {
  /** @internal Type-level brand so TypeScript can infer `T` from `EncryptedTable<T>`. */
  declare readonly _columnType: T

  constructor(
    public readonly tableName: string,
    public readonly columnBuilders: T,
  ) {}

  build(): TableDefinition {
    const builtColumns: Record<string, ColumnSchema> = {}
    for (const builder of Object.values(this.columnBuilders)) {
      // Key by the column's DB name (`getName()`), NOT the JS property name.
      // `encrypt`/`decrypt` look columns up in the config by `column.getName()`,
      // so a camelCase JS key mapping to a snake_case DB column (e.g.
      // `createdOn: types.Date('created_on')`) must register under
      // `created_on` or the FFI reports "column not found in Encrypt config".
      const name = builder.getName()
      // Two JS properties resolving to the same DB name would silently overwrite
      // here (later wins), dropping the first column's config. Fail loudly —
      // matching the duplicate-tableName guard in buildEncryptConfig and the
      // reserved-key guard in encryptedTable.
      if (Object.hasOwn(builtColumns, name)) {
        throw new Error(
          `[eql/v3]: duplicate column name "${name}" in table "${this.tableName}" — two columns resolve to the same DB name`,
        )
      }
      builtColumns[name] = builder.build()
    }
    return {
      tableName: this.tableName,
      columns: builtColumns,
    }
  }

  /**
   * Map each column's JS property name to its DB column name (`getName()`).
   * The model path matches user models by property name but must address the
   * encrypt config and FFI by DB name — `build()` keys columns by DB name, so
   * the two only agree when property == name. This recovers the mapping that
   * `build()` discards.
   *
   * NULL PROTOTYPE — load-bearing. Callers index this map by a column name that
   * ultimately comes from the database (`addJsonbCastsV3`, `filterColumnName`,
   * the mutation transform). On a plain object literal, a column named
   * `constructor` / `toString` / `valueOf` / `__proto__` resolves to an
   * inherited `Object.prototype` member, which is truthy — so a *plaintext*
   * column with such a name would be mistaken for a mapped encrypted column and
   * its `Object.prototype` value interpolated into the emitted select string.
   * `encryptedTable()` rejects such names as JS *properties*, but nothing
   * constrains the DB column names a table may contain.
   */
  buildColumnKeyMap(): Record<string, string> {
    const map = Object.create(null) as Record<string, string>
    for (const [property, builder] of Object.entries(this.columnBuilders)) {
      map[property] = builder.getName()
    }
    return map
  }
}

/**
 * Own instance members of {@link EncryptedTable} that a column name must not
 * shadow. Because {@link encryptedTable} copies column builders onto the
 * instance for accessor access (`users.email`), a column named e.g. `build`
 * would otherwise overwrite the method that {@link buildEncryptConfig} relies
 * on. `_columnType` is a type-only `declare` (no runtime property) so it is
 * listed explicitly here rather than caught by the `in` check below.
 */
const RESERVED_TABLE_KEYS = new Set([
  'tableName',
  'columnBuilders',
  '_columnType',
  'build',
  'buildColumnKeyMap',
])

/**
 * Whether a column name would collide with a reserved property on the table
 * object — either an own member ({@link RESERVED_TABLE_KEYS}) or any inherited
 * `Object.prototype` member (`constructor`, `toString`, `valueOf`,
 * `hasOwnProperty`, …). The `in` check covers the prototype chain so assigning
 * the column as an own property can never shadow a prototype method/accessor.
 */
function isReservedTableKey(tableBuilder: object, colName: string): boolean {
  return RESERVED_TABLE_KEYS.has(colName) || colName in tableBuilder
}

/**
 * Define a v3 encrypted table. Intentionally shadows the v2 `encryptedTable`
 * name but lives on the `/eql/v3` subpath — the importer picks the model by
 * import path. The returned object is also a column accessor (`users.email`).
 */
export function encryptedTable<T extends EncryptedV3TableColumn>(
  tableName: string,
  columns: T,
): EncryptedTable<T> & T {
  const tableBuilder = new EncryptedTable(
    tableName,
    columns,
  ) as EncryptedTable<T> & T

  for (const [colName, colBuilder] of Object.entries(columns)) {
    if (isReservedTableKey(tableBuilder, colName)) {
      throw new Error(
        `Column name "${colName}" collides with a reserved EncryptedTable property`,
      )
    }
    ;(tableBuilder as EncryptedV3TableColumn)[colName] = colBuilder
  }

  return tableBuilder
}

/**
 * Build an `EncryptConfig` (`v: 1`) from one or more v3 tables. Emits the same
 * shape as v2's `buildEncryptConfig`.
 */
export function buildEncryptConfig(
  ...tables: Array<EncryptedTable<EncryptedV3TableColumn>>
): EncryptConfig {
  const config: EncryptConfig = {
    v: 1,
    tables: {},
  }

  for (const tb of tables) {
    const tableDef = tb.build()
    // Config tables are keyed by name, so a duplicate would silently overwrite
    // the earlier table. Fail loudly instead. (v3-only additive guard; v2's
    // buildEncryptConfig keeps its existing silent-overwrite behavior.)
    if (Object.hasOwn(config.tables, tableDef.tableName)) {
      throw new Error(
        `[eql/v3]: duplicate table name "${tableDef.tableName}" passed to buildEncryptConfig — each table must have a unique name`,
      )
    }
    config.tables[tableDef.tableName] = tableDef.columns
  }

  return config
}

/**
 * Infer the plaintext (decrypted) shape from a v3 table schema. Each column maps
 * to the TypeScript type of its domain's `castAs` kind.
 */
export type InferPlaintext<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C>
    ? { [K in keyof C]: PlaintextForColumn<C[K]> }
    : never

/**
 * Infer the encrypted shape from a v3 table schema. See {@link InferPlaintext}
 * for why no key-remap filter is needed in the flat single-type model.
 */
export type InferEncrypted<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C> ? { [K in keyof C]: Encrypted } : never

// ---------------------------------------------------------------------------
// Typed-client surface helpers (@cipherstash/stack/v3)
// ---------------------------------------------------------------------------

/** Any v3 table, regardless of its column map. */
export type AnyV3Table = EncryptedTable<EncryptedV3TableColumn>

/** Union of the concrete column builders declared on a v3 table. */
export type ColumnsOf<T extends AnyV3Table> =
  T extends EncryptedTable<infer C> ? C[keyof C] : never

/**
 * Union of the *queryable* column builders on a v3 table. Storage-only columns
 * (whose {@link QueryTypesForColumn} is `never`) are filtered out, so they can't
 * be passed to a query method.
 */
export type QueryableColumnsOf<T extends AnyV3Table> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C]: [QueryTypesForColumn<C[K]>] extends [never]
          ? never
          : C[K]
      }[keyof C]
    : never

/**
 * The accepted input model for {@link import('@/encryption/v3').TypedEncryptionClient.encryptModel}.
 * `T` is inferred from the argument: keys that name a schema column are pinned to
 * the column's plaintext type (nullable if the field is nullable), so a wrong-typed
 * field fails assignability; all other keys pass through unchanged.
 */
export type V3ModelInput<Table extends AnyV3Table, T> = {
  [K in keyof T]: K extends keyof InferPlaintext<Table>
    ? null extends T[K]
      ? InferPlaintext<Table>[K] | null
      : InferPlaintext<Table>[K]
    : T[K]
}

/** The encrypted result model: schema columns become `Encrypted`, others pass through. */
export type V3EncryptedModel<Table extends AnyV3Table, T> = {
  [K in keyof T]: K extends keyof InferPlaintext<Table>
    ? null extends T[K]
      ? Encrypted | null
      : Encrypted
    : T[K]
}

/**
 * The decrypted result model: schema columns become their plaintext type, others
 * pass through. Structurally identical to {@link V3ModelInput} — decrypt yields
 * the same plaintext shape encrypt accepts — so it is aliased rather than
 * re-declared to keep the input and output shapes from silently drifting when
 * one copy is edited. The distinct name is kept for call-site readability.
 */
export type V3DecryptedModel<Table extends AnyV3Table, T> = V3ModelInput<
  Table,
  T
>
