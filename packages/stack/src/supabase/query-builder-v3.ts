import type { EncryptionClient } from '@/encryption'
import type { AnyV3Table } from '@/eql/v3'
import { EncryptedV3Column } from '@/eql/v3/columns'
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
  FilterOp,
  PendingOrCondition,
  SupabaseClientLike,
  SupabaseQueryBuilder,
} from './types'

/**
 * The subset of a v3 column builder the dialect relies on. Structural rather
 * than the concrete class union so the runtime `instanceof EncryptedV3Column`
 * gate and this type stay independent.
 *
 * Deliberately NOT `BuildableQueryColumn`'s `BuildableV3QueryableColumn` arm,
 * despite the overlapping members: that type pins `isQueryable(): true`, and
 * this map intentionally retains storage-only columns (whose `isQueryable()`
 * is `false`) so a filter on one produces a precise error instead of passing
 * through unencrypted.
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
 * EQL v3 dialect of {@link EncryptedQueryBuilderImpl} for native `eql_v3.*`
 * domain columns. The query mechanism is v2's — direct EQL operators over
 * PostgREST — with four narrow forks:
 *
 * - **Column recognition / naming** — v3 columns are `EncryptedV3Column`
 *   builders and may map a JS property name to a different DB column name
 *   (`buildColumnKeyMap`). Filters, select casts, and mutations resolve
 *   property → DB name; select casts alias the DB column back to the property
 *   (`prop:db_name::jsonb`) so result rows keep property keys.
 * - **Mutation encoding** — the raw encrypted payload object is sent (the
 *   `eql_v3.*` domains are `DOMAIN … AS jsonb`), not v2's `{ data: … }`
 *   composite wrap.
 * - **Query-term encoding** — every filter operand is the FULL storage
 *   envelope from `encrypt()`, serialized as jsonb text. This is load-bearing:
 *   each `eql_v3.*` domain CHECK requires the storage keys (`v`/`i`/`c` plus
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
  /** Built column schemas keyed by DB column name (for `cast_as`). */
  private columnSchemas: Record<string, ColumnSchema>
  /** Column builders keyed by BOTH property name and DB name. */
  private v3Columns: Record<string, V3ColumnLike>
  /**
   * Result-row key → DB column name for the columns the current select
   * produces, including user-chosen PostgREST aliases (`ts:created_at` keys
   * rows by `ts`). Populated by {@link buildSelectString}; consumed by
   * {@link postprocessDecryptedRow} so aliased date columns still get `Date`
   * reconstruction.
   */
  private selectKeyToDb: Record<string, string> = {}

  constructor(
    tableName: string,
    table: AnyV3Table,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
  ) {
    super(
      tableName,
      // The base class only ever calls BuildableTable members on the schema
      // (build / encryptModel plumbing); every v2-specific behaviour is
      // overridden below.
      table as unknown as EncryptedTable<EncryptedTableColumn>,
      encryptionClient,
      supabaseClient,
    )

    this.v3Table = table
    this.propToDb = table.buildColumnKeyMap()
    this.columnSchemas = table.build().columns

    this.v3Columns = {}
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

  protected override filterColumnName(column: string): string {
    return this.propToDb[column] ?? column
  }

  protected override buildSelectString(): string | null {
    if (this.selectColumns === null) return null
    const { select, keyToDb } = addJsonbCastsV3(
      this.selectColumns,
      this.propToDb,
    )
    this.selectKeyToDb = keyToDb
    return select
  }

  /** v3 domains are plain jsonb — send the raw payload, keyed by DB name. */
  protected override transformEncryptedMutationModel(
    model: Record<string, unknown>,
  ): Record<string, unknown> {
    const out: Record<string, unknown> = {}
    for (const [key, value] of Object.entries(model)) {
      out[this.propToDb[key] ?? key] = value
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
   *
   * INTERIM + single swap point. The full-envelope operand is a tracked
   * workaround (Linear CIP-3402), not the design: it carries a real
   * decryptable ciphertext `c` plus ALL of the column's index terms, and
   * PostgREST filters travel in GET query strings — so operands can land in
   * URL logs, proxies, and Supabase request logs (query terms are meant to
   * be index-terms-only). When the EQL term-only scalar query envelope (the
   * scalar analog of `eql_v3.jsonb_query`) ships, swapping the encryption
   * call inside THIS method — and its `JSON.stringify` wire encoding — must
   * be the ONLY change needed: every consuming seam (filter application,
   * `or`/`not` transforms, the wire-operator remap) treats the returned
   * operand as an opaque, already-encoded string and is encoding-agnostic.
   * Do not let operand-encoding knowledge leak out of this method.
   */
  protected override async encryptCollectedTerms(
    terms: ScalarQueryTerm[],
  ): Promise<unknown[]> {
    return Promise.all(
      terms.map(async (term) => {
        const column = term.column as unknown as V3ColumnLike
        const queryType = term.queryType ?? 'equality'
        const capabilities = column.getQueryCapabilities()

        // encrypt(null) short-circuits to null, which JSON.stringify would
        // turn into the literal string "null" — a silently-wrong operand.
        if (term.value == null) {
          throw new Error(
            `[supabase v3]: cannot encrypt a null filter value for column "${column.getName()}" — use .is('${column.getName()}', null) for NULL checks`,
          )
        }

        if (
          queryType !== 'equality' &&
          queryType !== 'orderAndRange' &&
          queryType !== 'freeTextSearch'
        ) {
          throw new Error(
            `[supabase v3]: query type "${queryType}" is not supported on scalar eql_v3 columns`,
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

  /**
   * The single source of the encrypted wire-operator remap: `like`/`ilike`
   * on an encrypted column become PostgREST `cs` (bloom-filter `@>`) — the
   * `eql_v3.*` domains define no LIKE operator. Every pattern-bearing seam
   * (`applyPatternFilter`, `notFilterOperator`, `transformOrConditions`)
   * derives its operator here so they cannot drift apart.
   */
  private encryptedFilterOp(op: string, wasEncrypted: boolean): string {
    return wasEncrypted && (op === 'like' || op === 'ilike') ? 'cs' : op
  }

  /** Encrypted pattern filters go through the bloom-filter `@>` (`cs`). */
  protected override applyPatternFilter(
    q: SupabaseQueryBuilder,
    column: string,
    op: 'like' | 'ilike',
    value: unknown,
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    const wireOp = this.encryptedFilterOp(op, wasEncrypted)
    if (wireOp !== op) {
      return q.filter(column, wireOp, value)
    }
    return super.applyPatternFilter(q, column, op, value, wasEncrypted)
  }

  protected override notFilterOperator(
    op: FilterOp,
    wasEncrypted: boolean,
  ): string {
    return this.encryptedFilterOp(op, wasEncrypted)
  }

  protected override transformOrConditions(
    conditions: PendingOrCondition[],
    encryptedIndexes: Set<number>,
  ): PendingOrCondition[] {
    return conditions.map((cond, j) => ({
      ...cond,
      column: this.filterColumnName(cond.column),
      op: this.encryptedFilterOp(cond.op, encryptedIndexes.has(j)) as FilterOp,
    }))
  }

  /** Rebuild `Date` values from the encrypt-config `cast_as`, mirroring the
   * typed v3 client's decrypt-model path. */
  protected override postprocessDecryptedRow(
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    // Row key → DB column name for every key an encrypted column can appear
    // under: the select's actual keys (including user-chosen aliases like
    // `ts:created_at`) plus the static property/DB names as a fallback for
    // paths with no recorded select.
    const keyToDb: Record<string, string> = { ...this.selectKeyToDb }
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      keyToDb[property] ??= dbName
      keyToDb[dbName] ??= dbName
    }

    const out: Record<string, unknown> = { ...row }
    for (const [key, dbName] of Object.entries(keyToDb)) {
      if (this.columnSchemas[dbName]?.cast_as !== 'date') continue
      const value = out[key]
      if (value == null || value instanceof Date) continue
      if (typeof value === 'string' || typeof value === 'number') {
        out[key] = new Date(value)
      }
    }
    return out
  }
}
