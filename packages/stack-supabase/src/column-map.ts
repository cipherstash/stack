import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { ColumnSchema } from '@cipherstash/stack/schema'
import type { BuildableQueryColumn } from '@cipherstash/stack/types'
import type { DbName } from './types'

/**
 * The subset of a v3 column builder the dialect relies on.
 *
 * This is BOTH the type and the runtime gate: `isV3ColumnLike` below probes
 * exactly these members. It must not become an `instanceof` check — see that
 * function's comment.
 */
export type V3ColumnLike = {
  getName(): string
  getEqlType(): string
  getQueryCapabilities(): {
    equality: boolean
    orderAndRange: boolean
    freeTextSearch: boolean
    /** Optional: only `public.eql_v3_json_search` (`types.Json`) carries it. */
    searchableJson?: boolean
  }
  build(): ColumnSchema
}

/**
 * Whether a column builder is an EQL v3 column, checked STRUCTURALLY.
 *
 * NOT `instanceof EncryptedV3Column`. tsup emits that class twice — once into
 * the chunk `dist/adapter-kit.js` imports, and once inline in
 * `dist/wasm-inline.js`, a separate esbuild run
 * (`packages/stack/tsup.config.ts:43-52`). A table authored with
 * `encryptedTable`/`types` from `@cipherstash/stack/wasm-inline` is built from
 * the second copy, so an `instanceof` against the first returned `false` for
 * every column: `v3Columns` came out empty and the adapter treated encrypted
 * columns as plaintext — filter operands reached PostgREST in the clear, while
 * `::jsonb` casts and decryption kept working (they read `buildColumnKeyMap()`
 * and the encrypt config, not this map).
 *
 * Mirrors `hasBuildColumnKeyMap` (`packages/stack/src/types.ts:276-283`), the
 * repo's canonical answer to the same problem, used identically at
 * `wasm-inline.ts:1361` — including its spelling: `'k' in obj && typeof (obj as
 * { k?: unknown }).k === 'function'`, one narrowed probe per member, rather
 * than one blanket `as Record<string, unknown>` over the whole object.
 *
 * Four probes, not two: a v2 column builder has `build()` and `getName()`
 * (`packages/stack/src/schema/index.ts:257,264`) but neither `getEqlType()` nor
 * `getQueryCapabilities()` (`eql/v3/columns.ts:445,450`).
 */
function isV3ColumnLike(builder: unknown): builder is V3ColumnLike {
  if (typeof builder !== 'object' || builder === null) return false
  return (
    'getName' in builder &&
    typeof (builder as { getName?: unknown }).getName === 'function' &&
    'getEqlType' in builder &&
    typeof (builder as { getEqlType?: unknown }).getEqlType === 'function' &&
    'getQueryCapabilities' in builder &&
    typeof (builder as { getQueryCapabilities?: unknown })
      .getQueryCapabilities === 'function' &&
    'build' in builder &&
    typeof (builder as { build?: unknown }).build === 'function'
  )
}

/**
 * Reject a declared property name that is also a DIFFERENT physical column.
 *
 * `select('*')` expands the introspected DB names into property names, so a
 * column renamed `created_at → createdAt` and a distinct plaintext column
 * literally named `createdAt` both emit the token `createdAt`, which
 * `addJsonbCastsV3` turns into `createdAt:created_at::jsonb` — twice. PostgREST
 * returns the encrypted column under that key and the plaintext one is never
 * selected, silently yielding the wrong value for a field the row type
 * guarantees.
 *
 * Nothing downstream can disambiguate the two, and `EncryptedTable.build()`'s
 * duplicate check only fires when two BUILDERS share a `getName()`. Refuse to
 * construct instead.
 */
function assertNoPropertyDbNameCollision(
  tableName: string,
  propToDb: Record<string, string>,
  allColumns: string[] | null,
): void {
  if (!allColumns) return
  const dbNames = new Set(allColumns)

  for (const [property, dbName] of Object.entries(propToDb)) {
    if (property === dbName) continue
    if (!dbNames.has(property)) continue
    throw new Error(
      `[supabase v3]: property "${property}" on table "${tableName}" renames DB column "${dbName}", but "${property}" is also a distinct column in the database — the two collide in select('*'). Rename the property, or drop the declared rename.`,
    )
  }
}

/**
 * Name and capability resolution for one table's columns.
 *
 * Every stage of the query pipeline addresses columns by BOTH the JS property
 * name a caller wrote and the DB name PostgREST must see, and each needs to ask
 * whether a given name is an encrypted v3 column and what it can be queried by.
 * Concentrating that here means the encrypt, DB-space, filter-apply and decrypt
 * modules take one collaborator instead of six correlated fields that must be
 * kept in lockstep.
 */
export class ColumnMap {
  /** JS property name → DB column name, for every encrypted column. */
  readonly propToDb: Record<string, string>
  /** Built column schemas keyed by DB column name (for `cast_as`, `indexes`). */
  readonly columnSchemas: Record<string, ColumnSchema>
  /** Every name an encrypted column answers to — property AND DB spelling.
   * Filters and select strings address columns by both, so recognition must
   * cover both. */
  readonly encryptedColumnNames: string[]

  /** DB column name → JS property name — the inverse of {@link propToDb}, used
   * to expand `select('*')` back into property names. Null prototype: a DB
   * column literally named `constructor` / `toString` would otherwise resolve
   * to an inherited `Object.prototype` member and be emitted as a select token. */
  private readonly dbToProp: Record<string, string>
  /** Column builders keyed by BOTH property name and DB name. */
  private readonly v3Columns: Record<string, V3ColumnLike>

  constructor(
    tableName: string,
    table: AnyV3Table,
    allColumns: string[] | null,
  ) {
    this.propToDb = table.buildColumnKeyMap()
    this.columnSchemas = table.build().columns

    this.dbToProp = Object.create(null) as Record<string, string>
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      this.dbToProp[dbName] = property
    }

    assertNoPropertyDbNameCollision(tableName, this.propToDb, allColumns)

    // Null-prototype: keyed by DB column names, and `validateTransforms` reads
    // it without an own-key guard — an inherited `constructor`/`toString` would
    // otherwise resolve truthy for a plaintext column of that name.
    this.v3Columns = Object.create(null) as Record<string, V3ColumnLike>
    for (const [property, builder] of Object.entries(table.columnBuilders)) {
      // FAIL CLOSED. `columnBuilders` is typed `EncryptedV3TableColumn`
      // (`eql/v3/table.ts:18-25`), so every entry is meant to be an encrypted v3
      // column. A builder that fails the structural probe is malformed input —
      // and silently skipping it is the one thing we must not do here: the
      // column would drop out of `v3Columns`, `isEncryptedColumn()` would return
      // false for it, and its filter operands would go to PostgREST as
      // PLAINTEXT. Refuse to construct instead, mirroring `build()`'s
      // fail-loudly-on-malformed stance (`eql/v3/table.ts:47-51`).
      if (!isV3ColumnLike(builder)) {
        throw new Error(
          `[supabase v3]: column "${property}" on table "${tableName}" is not a recognised EQL v3 column builder. Its filter operands would otherwise be sent to PostgREST unencrypted, so construction is refused. Author the table with \`encryptedTable\`/\`types\` from \`@cipherstash/stack/eql/v3\` or \`@cipherstash/stack/wasm-inline\`.`,
        )
      }
      const col = builder
      this.v3Columns[property] = col
      this.v3Columns[col.getName()] = col
    }

    this.encryptedColumnNames = Object.keys(this.v3Columns)
  }

  /** Resolve a JS property name to its DB column name. `Object.hasOwn` guards
   * the inherited-member hazard described on {@link EncryptedTable.buildColumnKeyMap}. */
  dbNameFor(name: string): string {
    return Object.hasOwn(this.propToDb, name) ? this.propToDb[name] : name
  }

  /**
   * Map a filter's column name to the DB column name PostgREST must see —
   * resolving a JS property name to its DB name.
   *
   * This is the ONLY place a {@link DbName} is minted. The
   * {@link SupabaseQueryBuilder} seam accepts nothing else, so every column
   * name reaching PostgREST must pass through here.
   */
  filterColumnName(column: string): DbName {
    return this.dbNameFor(column) as DbName
  }

  /**
   * Encrypted ordering columns sort by their `op` term, not by the envelope.
   *
   * `order=col->op` is the one ordering expression PostgREST can emit that
   * reaches the OPE term. It must NOT leak into filters — those compare whole
   * envelopes through the `eql_v3.*` operators — which is why this is its own
   * seam rather than a change to {@link filterColumnName}.
   *
   * The canonical EQL form is `ORDER BY eql_v3.ord_term(col)`, which returns
   * `eql_v3_internal.ope_cllw` — a domain over `bytea`, ordered by the native
   * btree. PostgREST cannot call a function, so it orders the `op` term where it
   * sits, inside the envelope. The two agree because the term is what
   * `ord_term()` returns.
   *
   * `->` (jsonb) rather than `->>` (text) keeps the comparison on the typed
   * value. Note this does NOT avoid the database collation: Postgres compares
   * jsonb strings with `varstr_cmp` under the default collation, exactly as it
   * does text. What makes the ordering collation-independent is the term itself
   * — fixed-width lowercase hex (`[0-9a-f]`, 130 chars for `integer_ord`, 82 for
   * `text_search`) — and every collation orders digits before letters and hex
   * letters among themselves. `match-bloom`'s sibling assertion pins that shape.
   *
   * This runs at column-name-mapping time (`transformToDbSpace`), BEFORE
   * `buildAndExecuteQuery` calls `validateTransforms`. For an encrypted column
   * with no `ope` index it therefore returns a bare `dbName` here — a name that
   * would sort by `jsonb_cmp` over the ciphertext if it reached PostgREST — but
   * it never does: `validateTransforms` throws (with a domain-specific reason)
   * before the query executes, so the bare name is only ever an intermediate
   * value on a request that is about to be rejected.
   */
  orderColumnName(column: string): DbName {
    const dbName = this.dbNameFor(column)
    const encrypted = this.v3Columns[column]
    if (!encrypted) return dbName as DbName

    return (
      this.columnSchemas[dbName]?.indexes?.ope ? `${dbName}->op` : dbName
    ) as DbName
  }

  /**
   * Expand the introspected column list (DB names) into JS property names.
   *
   * Load-bearing for `select('*')` on a DECLARED table that renames a column.
   * `addJsonbCastsV3` only emits the `prop:db_name::jsonb` alias — the thing
   * that makes PostgREST return the column under its property name — when the
   * token it sees is a property name. Feeding it the raw DB name instead takes
   * the unaliased `dbNames.has(...)` branch, so the row comes back keyed
   * `created_at` while the declared row type promises `createdAt`, silently
   * yielding `undefined` for a field TypeScript guarantees.
   *
   * A DB column with no encrypted builder (plaintext passthrough, and every
   * synthesized column, where property == DB name) maps to itself.
   */
  expandAllColumns(columns: string[]): string[] {
    return columns.map((dbName) =>
      Object.hasOwn(this.dbToProp, dbName) ? this.dbToProp[dbName] : dbName,
    )
  }

  /** True when `column` is one of this table's encrypted v3 columns. */
  isEncryptedV3Column(column: string): boolean {
    return Boolean(this.v3Columns[column])
  }

  /** True when `column` is an encrypted `types.Json` document column. */
  isSearchableJsonColumn(column: string): boolean {
    const builder: V3ColumnLike | undefined = this.v3Columns[column]
    return Boolean(builder?.getQueryCapabilities().searchableJson)
  }

  /** The encrypted builder for `column`, by either spelling. */
  encryptedColumn(column: string): V3ColumnLike | undefined {
    return this.v3Columns[column]
  }

  /** The built schema for a DB column name — `cast_as` and `indexes`. */
  schemaFor(dbName: string): ColumnSchema | undefined {
    return this.columnSchemas[dbName]
  }

  /** The encrypted builders as the term collector's column lookup. */
  queryColumnMap(): Record<string, BuildableQueryColumn> {
    // `V3ColumnLike` omits `isQueryable(): true`, which `BuildableV3QueryableColumn`
    // requires — and `v3Columns` intentionally holds storage-only columns, for which
    // `isQueryable()` is `false`. The collector consults `getQueryCapabilities()`
    // before using an entry (`query-encrypt.ts:513`), so the widening is safe;
    // narrowing the type would mean narrowing the map.
    // biome-ignore lint/plugin: storage-only v3 columns lack `isQueryable(): true`; widening is safe (see above).
    return this.v3Columns as unknown as Record<string, BuildableQueryColumn>
  }
}
