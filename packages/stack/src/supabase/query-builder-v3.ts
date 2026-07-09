import type { EncryptionClient } from '@/encryption'
import type { AnyV3Table } from '@/eql/v3'
import { DATE_LIKE_CASTS, EncryptedV3Column } from '@/eql/v3/columns'
import type {
  ColumnSchema,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'
import type { BuildableQueryColumn, ScalarQueryTerm } from '@/types'
import { logger } from '@/utils/logger'
import { addJsonbCastsV3 } from './helpers'
import {
  EncryptedQueryBuilderImpl,
  EncryptionFailedError,
} from './query-builder'
import type {
  DbName,
  DbPendingOrCondition,
  DbSelect,
  FilterOp,
  SupabaseClientLike,
  SupabaseQueryBuilder,
} from './types'

/** cast_as kinds that reconstruct to a JS `Date` — shared with the typed v3
 * client's decrypt-model path (see `encryption/v3.ts`). */
const DATE_LIKE_CAST_SET = new Set<string>(DATE_LIKE_CASTS)

/**
 * The subset of a v3 column builder the dialect relies on. Structural rather
 * than the concrete class union so the runtime `instanceof EncryptedV3Column`
 * gate and this type stay independent.
 */
type V3ColumnLike = {
  getName(): string
  getEqlType(): string
  getQueryCapabilities(): {
    equality: boolean
    orderAndRange: boolean
    freeTextSearch: boolean
  }
  build(): ColumnSchema
}

/**
 * EQL v3 dialect of {@link EncryptedQueryBuilderImpl} for native concrete-domain
 * columns (`public.*` type domains, `eql_v3` operators). The query mechanism is
 * v2's — direct EQL operators over PostgREST — with four narrow forks:
 *
 * - **Column recognition / naming** — v3 columns are `EncryptedV3Column`
 *   builders and may map a JS property name to a different DB column name
 *   (`buildColumnKeyMap`). Filters, select casts, and mutations resolve
 *   property → DB name; select casts alias the DB column back to the property
 *   (`prop:db_name::jsonb`) so result rows keep property keys.
 * - **Mutation encoding** — the raw encrypted payload object is sent (the
 *   `public.*` domains are `DOMAIN … AS jsonb`), not v2's `{ data: … }`
 *   composite wrap.
 * - **Query-term encoding** — every filter operand is the FULL storage
 *   envelope from `encrypt()`, serialized as jsonb text. This is load-bearing:
 *   each `public.*` domain CHECK requires the storage keys (`v`/`i`/`c` plus
 *   the domain's index terms), and the SQL operator functions coerce their
 *   jsonb operand into the domain — so a narrowed `encryptQuery` term (which
 *   carries no `c`) fails the CHECK with 23514 for EVERY domain, not just
 *   `text_search`. The full envelope satisfies the CHECK by construction and
 *   the operators extract the term they need (`eq_term`/`ord_term`/
 *   `match_term`).
 * - **`like`/`ilike`** — the v3 domains define no LIKE operator; free-text
 *   match is `@>` on the bloom filter. Encrypted pattern filters are emitted
 *   as PostgREST `cs` instead. (Match is tokenized + downcased, so `like` and
 *   `ilike` behave identically. For substring patterns to match, the column's
 *   match index should set `include_original: false` — with the default
 *   `true`, the full-envelope operand's bloom carries the whole pattern as an
 *   extra token that only matches when the pattern equals the stored value.)
 *
 * Decrypted rows additionally get `Date` reconstruction from the
 * encrypt-config `cast_as`, mirroring the typed v3 client.
 */
export class EncryptedQueryBuilderV3Impl<
  T extends Record<string, unknown> = Record<string, unknown>,
> extends EncryptedQueryBuilderImpl<T> {
  private v3Table: AnyV3Table
  /** JS property name → DB column name, for every encrypted column. */
  private propToDb: Record<string, string>
  /** DB column name → JS property name — the inverse of {@link propToDb}, used
   * to expand `select('*')` back into property names. Null prototype: a DB
   * column literally named `constructor` / `toString` would otherwise resolve
   * to an inherited `Object.prototype` member and be emitted as a select token. */
  private dbToProp: Record<string, string>
  /** Built column schemas keyed by DB column name (for `cast_as`). */
  private columnSchemas: Record<string, ColumnSchema>
  /** Column builders keyed by BOTH property name and DB name. */
  private v3Columns: Record<string, V3ColumnLike>

  constructor(
    tableName: string,
    table: AnyV3Table,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
    allColumns: string[] | null = null,
  ) {
    super(
      tableName,
      // The base class only ever calls BuildableTable members on the schema
      // (build / encryptModel plumbing); every v2-specific behaviour is
      // overridden below.
      table as unknown as EncryptedTable<EncryptedTableColumn>,
      encryptionClient,
      supabaseClient,
      allColumns,
    )

    this.v3Table = table
    this.propToDb = table.buildColumnKeyMap()
    this.columnSchemas = table.build().columns

    this.dbToProp = Object.create(null) as Record<string, string>
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      this.dbToProp[dbName] = property
    }

    // Null-prototype: keyed by DB column names, and `validateTransforms` reads
    // it without an own-key guard — an inherited `constructor`/`toString` would
    // otherwise resolve truthy for a plaintext column of that name.
    this.v3Columns = Object.create(null) as Record<string, V3ColumnLike>
    for (const [property, builder] of Object.entries(table.columnBuilders)) {
      if (builder instanceof EncryptedV3Column) {
        const col = builder as unknown as V3ColumnLike
        this.v3Columns[property] = col
        this.v3Columns[col.getName()] = col
      }
    }

    // The base class derives encrypted column names from build(), which v3
    // keys by DB name. Filters and select strings address columns by JS
    // property name, so recognition must cover both.
    this.encryptedColumnNames = Object.keys(this.v3Columns)
  }

  // ---------------------------------------------------------------------------
  // Dialect overrides
  // ---------------------------------------------------------------------------

  protected override getColumnMap(): Record<string, BuildableQueryColumn> {
    return this.v3Columns as unknown as Record<string, BuildableQueryColumn>
  }

  /** Resolve a JS property name to its DB column name. `Object.hasOwn` guards
   * the inherited-member hazard described on {@link EncryptedTable.buildColumnKeyMap}. */
  private dbNameFor(name: string): string {
    return Object.hasOwn(this.propToDb, name) ? this.propToDb[name] : name
  }

  protected override filterColumnName(column: string): DbName {
    return this.dbNameFor(column) as DbName
  }

  /**
   * Ordering by an encrypted column relies on the domain's ORE index. A
   * storage-only domain (`public.boolean`, `public.text`, …) has none, so
   * PostgREST would sort by the raw ciphertext envelope and return a
   * plausible-looking but meaningless row order. Reject it, mirroring the
   * capability guard {@link encryptCollectedTerms} applies to filters — that
   * guard is the only protection the untyped (no-`schemas`) surface has.
   *
   * A column absent from {@link v3Columns} is a plaintext passthrough.
   */
  protected override validateTransforms(): void {
    for (const t of this.transforms) {
      if (t.kind !== 'order') continue
      const column = this.v3Columns[t.column]
      if (!column) continue
      if (!column.getQueryCapabilities().orderAndRange) {
        throw new Error(
          `[supabase v3]: column "${column.getName()}" (${column.getEqlType()}) does not support ordering — declare the column with a domain that carries the orderAndRange capability`,
        )
      }
    }
  }

  protected override buildSelectString(): DbSelect | null {
    if (this.selectColumns === null) return null
    return addJsonbCastsV3(this.selectColumns, this.propToDb)
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
  protected override expandAllColumns(columns: string[]): string[] {
    return columns.map((dbName) =>
      Object.hasOwn(this.dbToProp, dbName) ? this.dbToProp[dbName] : dbName,
    )
  }

  /** v3 domains are plain jsonb — send the raw payload, keyed by DB name. */
  protected override transformEncryptedMutationModel(
    model: Record<string, unknown>,
  ): Record<string, unknown> {
    const out: Record<string, unknown> = Object.create(null)
    for (const [key, value] of Object.entries(model)) {
      out[this.dbNameFor(key)] = value
    }
    return out
  }

  protected override transformEncryptedMutationModels(
    models: Record<string, unknown>[],
  ): Record<string, unknown>[] {
    return models.map((model) => this.transformEncryptedMutationModel(model))
  }

  /**
   * Encrypt every filter operand as a full storage envelope (see the class
   * doc for why `encryptQuery` terms cannot be used), serialized to jsonb
   * text for the PostgREST filter value.
   */
  protected override async encryptCollectedTerms(
    terms: ScalarQueryTerm[],
  ): Promise<unknown[]> {
    return Promise.all(
      terms.map(async (term) => {
        const column = term.column as unknown as V3ColumnLike
        const queryType = term.queryType ?? 'equality'
        const capabilities = column.getQueryCapabilities()

        if (
          queryType !== 'equality' &&
          queryType !== 'orderAndRange' &&
          queryType !== 'freeTextSearch'
        ) {
          throw new Error(
            `[supabase v3]: query type "${queryType}" is not supported on scalar EQL v3 columns`,
          )
        }

        if (!capabilities[queryType]) {
          throw new Error(
            `[supabase v3]: column "${column.getName()}" (${column.getEqlType()}) does not support ${queryType} queries — declare the column with a domain that carries that capability`,
          )
        }

        const baseOp = this.encryptionClient.encrypt(term.value, {
          column,
          table: this.v3Table,
        })
        const op = this.lockContext
          ? baseOp.withLockContext(this.lockContext)
          : baseOp
        if (this.auditConfig) op.audit(this.auditConfig)

        const result = await op
        if (result.failure) {
          logger.error(
            `Supabase: failed to encrypt query terms for table "${this.tableName}"`,
          )

          throw new EncryptionFailedError(
            `Failed to encrypt query terms: ${result.failure.message}`,
            result.failure,
          )
        }

        return JSON.stringify(result.data)
      }),
    )
  }

  /** Encrypted pattern filters go through the bloom-filter `@>` (`cs`). */
  protected override applyPatternFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    op: 'like' | 'ilike',
    value: unknown,
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    if (wasEncrypted) {
      return q.filter(column, 'cs', value)
    }
    return super.applyPatternFilter(q, column, op, value, wasEncrypted)
  }

  protected override notFilterOperator(
    op: FilterOp,
    wasEncrypted: boolean,
  ): string {
    if (wasEncrypted && (op === 'like' || op === 'ilike')) {
      return 'cs'
    }
    return op
  }

  /**
   * Map `like`/`ilike` to `cs` on the conditions that were encrypted — the same
   * bloom-filter containment rewrite {@link applyPatternFilter} performs for
   * regular filters. Operator shaping stays here rather than in `toDbSpace`
   * because it depends on `wasEncrypted`, which is only known after encryption.
   *
   * Column names arrive already in DB-space (`toDbSpace`), so this no longer
   * translates them.
   */
  protected override transformOrConditions(
    conditions: DbPendingOrCondition[],
    encryptedIndexes: Set<number>,
  ): DbPendingOrCondition[] {
    return conditions.map((cond, j) => {
      const op =
        encryptedIndexes.has(j) && (cond.op === 'like' || cond.op === 'ilike')
          ? ('cs' as FilterOp)
          : cond.op
      return op === cond.op ? cond : { ...cond, op }
    })
  }

  /** Rebuild `Date` values from the encrypt-config `cast_as` (date/timestamp),
   * mirroring the typed v3 client's decrypt-model path. */
  protected override postprocessDecryptedRow(
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    const out: Record<string, unknown> = { ...row }
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      const castAs = this.columnSchemas[dbName]?.cast_as
      if (!DATE_LIKE_CAST_SET.has(castAs as string)) continue
      // Rows are keyed by property name when selected via the aliasing cast
      // helper, but a caller selecting by raw DB name gets DB-name keys.
      for (const key of property === dbName ? [property] : [property, dbName]) {
        const value = out[key]
        if (value == null || value instanceof Date) continue
        if (typeof value === 'string' || typeof value === 'number') {
          out[key] = new Date(value)
        }
      }
    }
    return out
  }
}
