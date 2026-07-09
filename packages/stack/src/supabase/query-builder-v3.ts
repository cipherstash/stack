import type { EncryptionClient } from '@/encryption'
import type { AnyV3Table } from '@/eql/v3'
import { DATE_LIKE_CASTS, EncryptedV3Column } from '@/eql/v3/columns'
import type {
  ColumnSchema,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'
import type {
  BuildableQueryColumn,
  QueryTypeName,
  ScalarQueryTerm,
} from '@/types'
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
 *   envelope from `encrypt()`, serialized as jsonb text.
 *
 *   NOT because narrowed terms fail the domain CHECK: the bundle defines a
 *   `public.<domain>_query` companion for each storage domain, whose CHECK
 *   requires `NOT (VALUE ? 'c')` — i.e. it accepts exactly the no-ciphertext
 *   shape `encryptQuery` produces. Those domains are simply unreachable from
 *   here. PostgREST has no syntax to cast a filter VALUE, and an uncast literal
 *   is ambiguous between the `_query` and `jsonb` `@>`/`=` overloads (42725 —
 *   the bundle says so itself, see `cipherstash-encrypt-v3-supabase.sql`, the
 *   `_query_types.sql` note). The reachable overload is the `jsonb` one, whose
 *   body coerces its operand to the STORAGE domain, which does require `c`.
 *   Independently, protect-ffi 0.28 throws `EQL_V3_QUERY_UNSUPPORTED` for any
 *   v3 scalar `encryptQuery`, so a narrowed term cannot be produced today.
 *
 *   The full envelope satisfies the storage-domain CHECK by construction, and
 *   the operators extract the term they need (`eq_term`/`ord_term`/
 *   `match_term`).
 * - **`contains`, not `like`/`ilike`** — the v3 domains define no LIKE operator.
 *   Free-text search is TOKEN CONTAINMENT: the bundle declares `@>` on each
 *   match domain (`CREATE OPERATOR @> … FUNCTION = eql_v3.contains`), whose body
 *   is `match_term(a) @> match_term(b)` — `smallint[]` containment of the two
 *   bloom filters. PostgREST reaches it as `cs`.
 *
 *   Match is tokenized + downcased, so `%` is NOT a wildcard — it is tokenized
 *   like any other character, and a `like` pattern is a category error. v3
 *   Drizzle omits `like`/`ilike` for this reason and exposes `contains`; so do
 *   we. The typed builder has no `like`; the runtime methods throw on an
 *   encrypted column and pass through on a plaintext one.
 *
 *   KNOWN BROKEN for real substrings, and not fixable from this file. The
 *   operand is a storage payload, so its bloom carries the whole needle as an
 *   extra `include_original` token, which the haystack's bloom cannot contain
 *   unless the needle equals the stored value or is exactly `token_length` (3)
 *   characters. v3 Drizzle's `contains` has the same defect for the same
 *   reason. Tracked in EQL; do not paper over it here.
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

    assertNoPropertyDbNameCollision(tableName, this.propToDb, allColumns)

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
   * Ordering by ANY encrypted v3 column is rejected — including the ORE-capable
   * ones, which is the non-obvious half.
   *
   * The `*_ord` domains are `CREATE DOMAIN … AS jsonb`, and the bundle declares
   * NO btree operator class on any domain — it actively lints against one
   * (`domain_opclass`), because an opclass on a domain bypasses operator
   * resolution. So `ORDER BY col` does not reach `eql_v3`'s ORE comparisons at
   * all: it resolves through jsonb's DEFAULT btree opclass, `jsonb_cmp`, and
   * sorts by the envelope's byte structure — keys compare alphabetically, so the
   * sort is effectively on the `bf` bloom array. No error, no warning, and a
   * stable, plausible-looking, meaningless row order.
   *
   * Correct ordering is `ORDER BY eql_v3.ord_term(col)`, which PostgREST's
   * `order=` parameter cannot express. The v3 Drizzle integration emits exactly
   * that (`sql-dialect.ts` `orderBy`), and proves it against live Postgres.
   *
   * The `>=`/`<=` operators ARE declared on the ord domains, so `gte`/`lte`
   * filters remain correct. Filtering and sorting resolve through different
   * machinery; only sorting is broken.
   *
   * A column absent from {@link v3Columns} is a plaintext passthrough, and
   * orders normally. This runtime guard is the only protection the untyped
   * (no-`schemas`) surface has.
   */
  protected override validateTransforms(): void {
    for (const t of this.transforms) {
      if (t.kind !== 'order') continue
      const column = this.v3Columns[t.column]
      if (!column) continue
      throw new Error(
        `[supabase v3]: cannot order by encrypted column "${column.getName()}" (${column.getEqlType()}) — PostgREST cannot emit \`ORDER BY eql_v3.ord_term("${column.getName()}")\`, and a bare \`ORDER BY\` sorts the raw ciphertext envelope, not the plaintext. Order by a plaintext column, expose \`eql_v3.ord_term()\` as a generated column or view and order by that, or use the EQL v3 Drizzle integration.`,
      )
    }
  }

  /**
   * Resolve a raw `.filter()` operator to the capability it exercises. Unlike
   * v2, the v3 operand is always the full storage envelope, so `queryType`
   * never selects a narrowing — it only tells {@link encryptCollectedTerms}
   * which capability to demand of the column. Getting it wrong therefore
   * produces a wrong accept/reject, not a wrong ciphertext: the base class's
   * `'equality'` default rejects `.filter('bio', 'cs', …)` on a
   * `public.text_match` column, the one query that column can answer.
   *
   * Unknown operators throw rather than silently defaulting to equality, which
   * would encrypt a term the column may not even be able to compare.
   */
  protected override queryTypeForRawOp(operator: string): QueryTypeName {
    switch (operator) {
      case 'cs':
        return 'freeTextSearch'
      case 'gt':
      case 'gte':
      case 'lt':
      case 'lte':
        return 'orderAndRange'
      case 'eq':
      case 'neq':
      case 'in':
      case 'is':
        return 'equality'
      default:
        throw new Error(
          `[supabase v3]: unsupported raw filter operator "${operator}" on an encrypted column`,
        )
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

  /**
   * `like`/`ilike` do not exist on the v3 surface (see the class doc). The
   * typed builder omits them, but an untyped JS caller can still reach them —
   * refuse loudly rather than emit a `~~` the domain has no operator for.
   *
   * A plaintext column is a genuine PostgREST text column, so `like` there is
   * exactly what the caller means; let it through.
   */
  private assertNotEncryptedPattern(column: string, op: string): void {
    if (!this.v3Columns[column]) return
    throw new Error(
      `[supabase v3]: "${op}" is not supported on encrypted column "${column}" — EQL v3 free-text search is token containment, not SQL wildcard matching ("%" is tokenized like any other character). Use contains().`,
    )
  }

  override like(column: string, pattern: string): this {
    this.assertNotEncryptedPattern(column, 'like')
    return super.like(column, pattern)
  }

  override ilike(column: string, pattern: string): this {
    this.assertNotEncryptedPattern(column, 'ilike')
    return super.ilike(column, pattern)
  }

  /**
   * Encrypted `contains` goes through the bloom-filter `@>`, which the bundle
   * declares on the domain as PostgREST's `cs`. The operand is the full storage
   * envelope; `eql_v3.contains` extracts the `bf` array from both sides.
   *
   * Emitted via `filter(col, 'cs', json)` rather than `q.contains(col, json)`:
   * postgrest-js's `contains` re-serializes a non-string operand, and our
   * operand is already `JSON.stringify`d.
   */
  protected override applyContainsFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    value: unknown,
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    if (wasEncrypted) {
      return q.filter(column, 'cs', value)
    }
    return super.applyContainsFilter(q, column, value, wasEncrypted)
  }

  protected override notFilterOperator(
    op: FilterOp,
    wasEncrypted: boolean,
  ): string {
    if (wasEncrypted && op === 'contains') {
      return 'cs'
    }
    return op
  }

  /**
   * `.or()` string conditions carry raw PostgREST operators, so a free-text
   * condition arrives as `cs` — not a {@link FilterOp}. Resolve it through the
   * same table the raw `.filter()` path uses, so `.or('amount.cs.5')` on an
   * `integer_ord` column is rejected by the capability guard rather than
   * silently encrypted as an equality term.
   */
  protected override queryTypeForOrOp(op: FilterOp): QueryTypeName {
    if (op === 'contains') return 'freeTextSearch'
    return this.queryTypeForRawOp(op)
  }

  /**
   * Rewrite the structured form's `contains` to the PostgREST operator token
   * `cs` before the or-string is rebuilt. String-form callers already write
   * `cs` — PostgREST syntax — so those pass through untouched.
   *
   * Operator shaping stays here rather than in `toDbSpace` because it depends
   * on `wasEncrypted`, which is only known after encryption. Column names
   * arrive already in DB-space.
   */
  protected override transformOrConditions(
    conditions: DbPendingOrCondition[],
    encryptedIndexes: Set<number>,
  ): DbPendingOrCondition[] {
    return conditions.map((cond, j) => {
      const op =
        encryptedIndexes.has(j) && cond.op === 'contains'
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
