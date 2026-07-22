import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import {
  DATE_LIKE_CASTS,
  EncryptedV3Column,
  logger,
  matchNeedleError,
  parseSelectorSegments,
  reconstructSelectorDocument,
  unsupportedLeafReason,
} from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import {
  type EncryptionError,
  EncryptionErrorTypes,
} from '@cipherstash/stack/errors'
import type { LockContextInput } from '@cipherstash/stack/identity'
import type { ColumnSchema } from '@cipherstash/stack/schema'
import type {
  BuildableQueryColumn,
  Encrypted,
  EncryptedQueryResult,
  QueryTypeName,
  ScalarQueryTerm,
} from '@cipherstash/stack/types'
import {
  addJsonbCastsV3,
  formatContainmentOperand,
  formatInListOperand,
  isEncryptableTerm,
  isEncryptedColumn,
  mapFilterOpToQueryType,
  parseOrString,
  rebuildOrString,
  selectKeyToDbV3,
} from './helpers'
import type {
  DbConflictList,
  DbFilterString,
  DbMutationOp,
  DbMutationOptions,
  DbName,
  DbPendingOrCondition,
  DbPendingOrFilter,
  DbQuerySpace,
  DbSelect,
  DbTransformOp,
  EncryptedSupabaseError,
  EncryptedSupabaseResponse,
  FilterOp,
  MutationOp,
  PendingFilter,
  PendingMatchFilter,
  PendingNotFilter,
  PendingOrCondition,
  PendingOrFilter,
  PendingRawFilter,
  ResultMode,
  SupabaseClientLike,
  SupabaseQueryBuilder,
  TransformOp,
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
    /** Optional: only `public.eql_v3_json_search` (`types.Json`) carries it. */
    searchableJson?: boolean
  }
  build(): ColumnSchema
}

/**
 * Validate an encrypted-JSON containment operand: a NON-EMPTY plain object or a
 * non-empty array. Everything else is rejected with an actionable steer:
 *
 * - Scalars/strings: the caller meant free-text (`matches` on a text column) or
 *   a selector — a raw JSON string is NOT parsed, by design (parsing would make
 *   `'{"a":1}'` and `{a:1}` silently different queries on other surfaces).
 * - Non-plain objects (`Date`, `Map`, `RegExp`, class instances): these JSON-
 *   serialize to scalars or `{}` — not the sub-document the caller believes.
 * - `{}` and `[]`: jsonb containment holds for EVERY document (`doc @> '{}'`),
 *   so an accidentally-empty needle would silently return (and decrypt) the
 *   whole table. The Drizzle adapter rejects the same needle for the same
 *   reason — the two first-party adapters must agree that this is an error.
 */
function assertJsonContainmentOperand(column: string, value: unknown): void {
  const isPlainObject =
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  if (!isPlainObject && !Array.isArray(value)) {
    // Array.isArray is false on this branch by construction, so the label only
    // distinguishes null / non-plain object / scalar.
    const got =
      value === null
        ? 'null'
        : typeof value === 'object'
          ? (value as object).constructor?.name || 'a non-plain object'
          : typeof value
    throw new Error(
      `[supabase v3]: encrypted JSON containment on column "${column}" takes a sub-document (plain object or array) to match, got ${got}.`,
    )
  }
  const empty = Array.isArray(value)
    ? value.length === 0
    : Object.keys(value as object).length === 0
  if (empty) {
    throw new Error(
      `[supabase v3]: encrypted JSON containment on column "${column}" cannot take an empty ${Array.isArray(value) ? 'array' : 'object'} needle: it matches every row. Pass a non-empty sub-document, or omit the predicate to select all rows.`,
    )
  }
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
 * A deferred query builder that wraps Supabase's query builder to automatically
 * handle encryption and decryption of data for native EQL v3 concrete-domain
 * columns (`public.*` type domains, `eql_v3` operators).
 *
 * All chained operations are recorded synchronously. When the builder is awaited,
 * it encrypts mutation data, adds `::jsonb` casts, batch-encrypts filter values,
 * executes the real Supabase query, and decrypts results.
 *
 * v3 columns are `EncryptedV3Column` builders and may map a JS property name to a
 * different DB column name (`buildColumnKeyMap`). Filters, select casts, and
 * mutations resolve property → DB name; select casts alias the DB column back to
 * the property (`prop:db_name::jsonb`) so result rows keep property keys. The raw
 * encrypted payload object is sent on mutations (the `public.*` domains are
 * `DOMAIN … AS jsonb`), and scalar equality/range filters use the FULL storage
 * envelope from `encrypt()`, serialized as jsonb text.
 *
 * EQL 3.0.2 removed the storage/jsonb escape hatch for free-text and JSON
 * operators: those now require typed query-domain operands PostgREST cannot
 * express. The factory reads the installed EQL version and this builder fails
 * those operators before encryption, so a decryptable storage envelope never
 * enters a GET URL.
 *
 * Decrypted rows additionally get `Date` reconstruction from the encrypt-config
 * `cast_as`, mirroring the typed v3 client. `decryptModel`/`bulkDecryptModels`
 * are generation-agnostic in `@cipherstash/stack`, so a stored EQL v2 payload
 * still decrypts through this builder's read path.
 */
export class EncryptedQueryBuilderImpl<
  T extends Record<string, unknown> = Record<string, unknown>,
> {
  protected tableName: string
  protected table: AnyV3Table
  protected encryptionClient: EncryptionClient
  protected supabaseClient: SupabaseClientLike
  protected encryptedColumnNames: string[]
  /** All column names for the table (encrypted + plaintext), in ordinal order,
   * used to expand `select('*')`. `null` when the caller supplied no column
   * list (a v3 client that could not introspect). */
  protected allColumns: string[] | null = null

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
  /** EQL 3.0.2+ requires query-domain casts PostgREST cannot express. */
  private queryDomainsRequired: boolean

  // Recorded operations
  protected mutation: MutationOp | null = null
  protected selectColumns: string | null = null
  protected selectOptions:
    | { head?: boolean; count?: 'exact' | 'planned' | 'estimated' }
    | undefined = undefined
  protected filters: PendingFilter[] = []
  protected orFilters: PendingOrFilter[] = []
  protected matchFilters: PendingMatchFilter[] = []
  protected notFilters: PendingNotFilter[] = []
  protected rawFilters: PendingRawFilter[] = []
  protected transforms: TransformOp[] = []
  protected resultMode: ResultMode = 'array'
  protected shouldThrowOnError = false

  // Encryption-specific state
  protected lockContext: LockContextInput | null = null
  protected auditConfig: AuditConfig | null = null

  constructor(
    tableName: string,
    table: AnyV3Table,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
    allColumns: string[] | null = null,
    queryDomainsRequired = false,
  ) {
    this.tableName = tableName
    this.table = table
    this.encryptionClient = encryptionClient
    this.supabaseClient = supabaseClient
    this.allColumns = allColumns
    this.queryDomainsRequired = queryDomainsRequired
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

    // Filters and select strings address columns by JS property name AND by DB
    // name, so recognition must cover both.
    this.encryptedColumnNames = Object.keys(this.v3Columns)
  }

  // ---------------------------------------------------------------------------
  // Mutation methods
  // ---------------------------------------------------------------------------

  select(
    columns = '*',
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): this {
    if (columns === '*') {
      if (this.allColumns === null || this.allColumns.length === 0) {
        throw new Error(
          "encryptedSupabase does not support select('*'). Please list columns explicitly so that encrypted columns can be cast with ::jsonb.",
        )
      }
      this.selectColumns = this.expandAllColumns(this.allColumns).join(', ')
    } else {
      this.selectColumns = columns
    }
    this.selectOptions = options
    return this
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
  protected expandAllColumns(columns: string[]): string[] {
    return columns.map((dbName) =>
      Object.hasOwn(this.dbToProp, dbName) ? this.dbToProp[dbName] : dbName,
    )
  }

  insert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      defaultToNull?: boolean
      onConflict?: string
    },
  ): this {
    this.mutation = {
      kind: 'insert',
      data: data as Record<string, unknown> | Record<string, unknown>[],
      options,
    }
    return this
  }

  update(
    data: Partial<T>,
    options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): this {
    this.mutation = {
      kind: 'update',
      data: data as Record<string, unknown>,
      options,
    }
    return this
  }

  upsert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      onConflict?: string
      ignoreDuplicates?: boolean
      defaultToNull?: boolean
    },
  ): this {
    this.mutation = {
      kind: 'upsert',
      data: data as Record<string, unknown> | Record<string, unknown>[],
      options,
    }
    return this
  }

  delete(options?: { count?: 'exact' | 'planned' | 'estimated' }): this {
    this.mutation = { kind: 'delete', options }
    return this
  }

  // ---------------------------------------------------------------------------
  // Filter methods
  // ---------------------------------------------------------------------------

  eq(column: string, value: unknown): this {
    this.filters.push({ op: 'eq', column, value })
    return this
  }

  neq(column: string, value: unknown): this {
    this.filters.push({ op: 'neq', column, value })
    return this
  }

  gt(column: string, value: unknown): this {
    this.filters.push({ op: 'gt', column, value })
    return this
  }

  gte(column: string, value: unknown): this {
    this.filters.push({ op: 'gte', column, value })
    return this
  }

  lt(column: string, value: unknown): this {
    this.filters.push({ op: 'lt', column, value })
    return this
  }

  lte(column: string, value: unknown): this {
    this.filters.push({ op: 'lte', column, value })
    return this
  }

  /**
   * `like`/`ilike` on an ENCRYPTED column are a best-effort compatibility shim,
   * delegated to `matches`. EQL v3 free-text search is fuzzy bloom token
   * matching, not SQL pattern matching, so the result is APPROXIMATE — matching
   * is case-insensitive and one-sided (may false-positive), and anchoring is
   * lost. Leading/trailing `%` are stripped; an internal `%` or any `_` cannot be
   * approximated by trigram matching and throws. A plaintext column keeps real
   * SQL LIKE.
   */
  like(column: string, pattern: string): this {
    if (!this.isEncryptedV3Column(column)) {
      this.filters.push({ op: 'like', column, value: pattern })
      return this
    }
    return this.matches(column, this.likeNeedle(column, 'like', pattern))
  }

  ilike(column: string, pattern: string): this {
    if (!this.isEncryptedV3Column(column)) {
      this.filters.push({ op: 'ilike', column, value: pattern })
      return this
    }
    return this.matches(column, this.likeNeedle(column, 'ilike', pattern))
  }

  /**
   * `contains` on the v3 surface is EXACT containment: native jsonb/array `@>`
   * on a plaintext column, ENCRYPTED ste_vec `@>` on a `types.Json` column (the
   * sub-document operand is storage-encrypted whole; every leaf must match at
   * its path — #650). On an encrypted match/search TEXT column containment is
   * not the operation (that is the fuzzy `matches`), so refuse loudly rather
   * than silently emit a bloom match under a name that promises exactness.
   */
  contains(column: string, value: unknown): this {
    if (this.isSearchableJsonColumn(column)) {
      this.assertPostgrestCanQueryEncryptedOperator('contains', column)
      // Same validator the term resolver enforces — failing here just surfaces
      // the error at the call site instead of at execution.
      assertJsonContainmentOperand(column, value)
      this.filters.push({ op: 'contains', column, value })
      return this
    }
    if (this.isEncryptedV3Column(column)) {
      throw new Error(
        `[supabase v3]: contains() is native (exact) containment and does not apply to encrypted column "${column}". Use matches() for encrypted free-text search.`,
      )
    }
    this.filters.push({ op: 'contains', column, value })
    return this
  }

  /**
   * `matches` is the encrypted free-text operator: fuzzy bloom-filter token
   * matching, one-sided (may false-positive), NOT containment. It requires an
   * encrypted match/search column; on a plaintext column, `contains` (native
   * `@>`) is what the caller means — and on an encrypted JSON column,
   * `contains`/`selectorEq` are (matching a document is containment, not
   * free-text). Guarded here because both spellings collect the same
   * `freeTextSearch` term, which the capability resolver would otherwise
   * silently accept as containment of the raw string.
   */
  matches(column: string, value: unknown): this {
    if (this.isSearchableJsonColumn(column)) {
      throw new Error(
        `[supabase v3]: matches() is encrypted free-text search and does not apply to encrypted JSON column "${column}". Use contains("${column}", subDocument) or selectorEq("${column}", path, value).`,
      )
    }
    if (!this.isEncryptedV3Column(column)) {
      throw new Error(
        `[supabase v3]: matches() is encrypted free-text search and requires an encrypted column; "${column}" is not one. Use contains() for native containment.`,
      )
    }
    this.assertPostgrestCanQueryEncryptedOperator('matches', column)
    this.filters.push({ op: 'matches', column, value })
    return this
  }

  is(column: string, value: null | boolean): this {
    this.filters.push({ op: 'is', column, value })
    return this
  }

  in(column: string, values: unknown[]): this {
    this.filters.push({ op: 'in', column, value: values })
    return this
  }

  filter(column: string, operator: string, value: unknown): this {
    this.rawFilters.push({ column, operator, value })
    return this
  }

  /**
   * `not(col, 'contains', …)` on an encrypted TEXT column would negate a fuzzy
   * bloom match under the `contains` name — the exact confusion #617 removes —
   * because the `not()` path rewrites the `contains` spelling to the `cs` wire
   * operator. Reject it and steer to the `matches` spelling (or the raw `cs`
   * operator, which is honest about the wire op).
   *
   * On an encrypted JSON column negated containment IS the honest exact
   * operation (`not.cs` over ste_vec containment — {@link selectorNe} compiles
   * to it), so it passes through. Plaintext columns keep native negated
   * containment, and every other operator is recorded unchanged.
   */
  not(column: string, operator: string, value: unknown): this {
    if (
      operator === 'contains' &&
      this.isEncryptedV3Column(column) &&
      !this.isSearchableJsonColumn(column)
    ) {
      throw new Error(
        `[supabase v3]: not("${column}", 'contains', …) does not apply to encrypted column "${column}" — that is fuzzy free-text matching, not containment. Use not("${column}", 'matches', …) or the raw 'cs' operator.`,
      )
    }
    // Mirror of the matches() guard: a `matches` spelling on a JSON column
    // would otherwise resolve to containment (the two share the `cs` wire op),
    // silently negating an EXACT operation under a name that promises FUZZY.
    if (operator === 'matches' && this.isSearchableJsonColumn(column)) {
      throw new Error(
        `[supabase v3]: not("${column}", 'matches', …) does not apply to encrypted JSON column "${column}" — matches() is free-text search. Use not("${column}", 'contains', subDocument) or selectorNe("${column}", path, value).`,
      )
    }
    this.notFilters.push({ column, op: operator as FilterOp, value })
    return this
  }

  or(
    filtersOrConditions: string | PendingOrCondition[],
    options?: { referencedTable?: string; foreignTable?: string },
  ): this {
    if (typeof filtersOrConditions === 'string') {
      this.orFilters.push({
        kind: 'string',
        value: filtersOrConditions,
        referencedTable: options?.referencedTable ?? options?.foreignTable,
      })
    } else {
      this.orFilters.push({
        kind: 'structured',
        conditions: filtersOrConditions,
      })
    }
    return this
  }

  match(query: Record<string, unknown>): this {
    this.matchFilters.push({ query })
    return this
  }

  /**
   * Encrypted JSONPath-selector equality: matches rows whose document carries
   * exactly `value` at `path`. Equality at a path IS containment of the
   * path-shaped needle (`{user: {role: 'admin'}}`), so this compiles to
   * {@link contains} — the ste_vec entry at the selector matches on its
   * equality/ordering term. Selector ORDERING (`gt`/`lt`/…) is not expressible
   * over PostgREST until the bundle grows a needle-comparison overload
   * (cipherstash/encrypt-query-language#407); the Drizzle adapter's
   * `ops.selector()` supports it today.
   */
  selectorEq(column: string, path: string, value: unknown): this {
    this.assertPostgrestCanQueryEncryptedOperator('selectorEq', column)
    const needle = this.selectorNeedle('selectorEq', column, path, value)
    return this.contains(column, needle)
  }

  /**
   * Encrypted JSONPath-selector inequality: rows whose document does NOT carry
   * `value` at `path` — INCLUDING rows where the path is absent AND rows whose
   * document column is SQL NULL, matching the Drizzle selector's `ne` (whose
   * `OR entry IS NULL` arm covers both absence cases). A bare `not.cs` would
   * drop NULL documents under three-valued logic (`NOT (NULL @> x)` is NULL),
   * so this compiles to a structured OR:
   * `column.is.null, column.not.cs.<needle>` — the containment condition's
   * operand is encrypted through the normal or-condition term path.
   */
  selectorNe(column: string, path: string, value: unknown): this {
    this.assertPostgrestCanQueryEncryptedOperator('selectorNe', column)
    const needle = this.selectorNeedle('selectorNe', column, path, value)
    return this.or([
      { column, op: 'is', value: null },
      { column, op: 'contains', negate: true, value: needle },
    ])
  }

  // ---------------------------------------------------------------------------
  // Transform methods (passthrough)
  // ---------------------------------------------------------------------------

  order(
    column: string,
    options?: {
      ascending?: boolean
      nullsFirst?: boolean
      referencedTable?: string
      foreignTable?: string
    },
  ): this {
    this.transforms.push({ kind: 'order', column, options })
    return this
  }

  limit(
    count: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): this {
    this.transforms.push({ kind: 'limit', count, options })
    return this
  }

  range(
    from: number,
    to: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): this {
    this.transforms.push({ kind: 'range', from, to, options })
    return this
  }

  single(): this {
    this.resultMode = 'single'
    this.transforms.push({ kind: 'single' })
    return this
  }

  maybeSingle(): this {
    this.resultMode = 'maybeSingle'
    this.transforms.push({ kind: 'maybeSingle' })
    return this
  }

  csv(): this {
    this.transforms.push({ kind: 'csv' })
    return this
  }

  abortSignal(signal: AbortSignal): this {
    this.transforms.push({ kind: 'abortSignal', signal })
    return this
  }

  throwOnError(): this {
    this.shouldThrowOnError = true
    this.transforms.push({ kind: 'throwOnError' })
    return this
  }

  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilderImpl<U> {
    // Type-level cast only; builder state is preserved
    return this as unknown as EncryptedQueryBuilderImpl<U>
  }

  // ---------------------------------------------------------------------------
  // Encryption-specific methods
  // ---------------------------------------------------------------------------

  withLockContext(lockContext: LockContextInput): this {
    this.lockContext = lockContext
    return this
  }

  audit(config: AuditConfig): this {
    this.auditConfig = config
    return this
  }

  // ---------------------------------------------------------------------------
  // PromiseLike implementation (deferred execution)
  // ---------------------------------------------------------------------------

  then<TResult1 = EncryptedSupabaseResponse<T[]>, TResult2 = never>(
    onfulfilled?:
      | ((
          value: EncryptedSupabaseResponse<T[]>,
        ) => TResult1 | PromiseLike<TResult1>)
      | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected)
  }

  // ---------------------------------------------------------------------------
  // Core execution
  // ---------------------------------------------------------------------------

  protected async execute(): Promise<EncryptedSupabaseResponse<T[]>> {
    try {
      logger.debug(`Supabase encrypted query on table "${this.tableName}".`)

      // 1. Encrypt mutation data
      const encryptedMutation = await this.encryptMutationData()

      // 2. Build select string with ::jsonb casts
      const selectString = this.buildSelectString()

      // 3. Translate every recorded column name into DB-space, once.
      const dbSpace = this.toDbSpace()

      // 4. Batch-encrypt filter values
      const encryptedFilters = await this.encryptFilterValues(dbSpace)

      // 5. Build and execute real Supabase query
      const result = await this.buildAndExecuteQuery(
        encryptedMutation,
        selectString,
        encryptedFilters,
        dbSpace,
      )

      // 6. Decrypt results
      return await this.decryptResults(result)
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err)
      logger.error(
        `Supabase encrypted query failed on table "${this.tableName}": ${message}`,
      )

      // A failure inside any of the encrypt/decrypt steps above is thrown as an
      // `EncryptionFailedError` wrapping the operation's `EncryptionError` (or a
      // synthesized one for its contract-violation cases). Thread it through so
      // callers can branch on `error.encryptionError`; a plain PostgREST/API
      // error is not an `EncryptionFailedError` and leaves it unset.
      const error: EncryptedSupabaseError = {
        message,
        encryptionError:
          err instanceof EncryptionFailedError
            ? err.encryptionError
            : undefined,
      }

      if (this.shouldThrowOnError) {
        throw err
      }

      return {
        data: null,
        error,
        count: null,
        status: 500,
        statusText: 'Encryption Error',
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Step 1: Encrypt mutation data
  // ---------------------------------------------------------------------------

  protected async encryptMutationData(): Promise<
    Record<string, unknown> | Record<string, unknown>[] | null
  > {
    if (!this.mutation) return null

    if (this.mutation.kind === 'delete') return null

    const data = this.mutation.data

    if (Array.isArray(data)) {
      // Bulk encrypt
      const baseOp = this.encryptionClient.bulkEncryptModels(data, this.table)
      const op = this.lockContext
        ? baseOp.withLockContext(this.lockContext)
        : baseOp
      if (this.auditConfig) op.audit(this.auditConfig)

      const result = await op
      if (result.failure) {
        logger.error(
          `Supabase: failed to encrypt models for table "${this.tableName}"`,
        )

        throw new EncryptionFailedError(
          `Failed to encrypt models: ${result.failure.message}`,
          result.failure,
        )
      }

      return this.transformEncryptedMutationModels(result.data)
    }

    // Single model
    const baseOp = this.encryptionClient.encryptModel(data, this.table)
    const op = this.lockContext
      ? baseOp.withLockContext(this.lockContext)
      : baseOp
    if (this.auditConfig) op.audit(this.auditConfig)

    const result = await op
    if (result.failure) {
      logger.error(
        `Supabase: failed to encrypt model for table "${this.tableName}"`,
      )

      throw new EncryptionFailedError(
        `Failed to encrypt model: ${result.failure.message}`,
        result.failure,
      )
    }

    return this.transformEncryptedMutationModel(result.data)
  }

  /**
   * Encode an encrypted model for the Supabase request body. The native
   * `eql_v3.*` domains are plain jsonb, so the raw encrypted payload is sent
   * (keyed by DB column name).
   */
  protected transformEncryptedMutationModel(
    model: Record<string, unknown>,
  ): Record<string, unknown> {
    const out: Record<string, unknown> = Object.create(null)
    for (const [key, value] of Object.entries(model)) {
      out[this.dbNameFor(key)] = value
    }
    return out
  }

  protected transformEncryptedMutationModels(
    models: Record<string, unknown>[],
  ): Record<string, unknown>[] {
    return models.map((model) => this.transformEncryptedMutationModel(model))
  }

  // ---------------------------------------------------------------------------
  // Step 2: Build select string with casts
  // ---------------------------------------------------------------------------

  protected buildSelectString(): DbSelect | null {
    if (this.selectColumns === null) return null
    return addJsonbCastsV3(this.selectColumns, this.propToDb)
  }

  // ---------------------------------------------------------------------------
  // Step 3: Encrypt filter values
  // ---------------------------------------------------------------------------

  protected async encryptFilterValues(
    dbSpace: DbQuerySpace,
  ): Promise<EncryptedFilterState> {
    // Collect all terms that need encryption
    const terms: ScalarQueryTerm[] = []
    const termMap: TermMapping[] = []

    const tableColumns = this.getColumnMap()

    const pushTerm = (
      value: JsPlaintext,
      column: ScalarQueryTerm['column'],
      queryType: QueryTypeName,
      mapping: TermMapping,
    ) => {
      terms.push({
        value,
        column,
        table: this.table,
        queryType,
        returnType: 'composite-literal',
      })
      termMap.push(mapping)
    }

    /**
     * Collect one term per element of an `in`-list operand.
     *
     * Element-wise is the only correct encoding: encrypting the array as ONE
     * value collapses `(a,b)` into a single ciphertext that matches nothing. A
     * null element is SQL NULL and passes through unencrypted; the applier
     * restores it by index, which is why the mapping carries `inIndex`.
     *
     * Shared by the regular-`in`, `not(…,'in',…)` and or-condition paths. They
     * drifted apart once already — the `not` path went unfixed while the other
     * two encrypted element-wise — so they are kept in lockstep here rather than
     * spelled out three times.
     */
    const collectInListTerms = (
      op: FilterOp,
      values: readonly unknown[],
      column: ScalarQueryTerm['column'],
      queryType: QueryTypeName,
      mappingFor: (inIndex: number) => TermMapping,
    ) => {
      for (let j = 0; j < values.length; j++) {
        if (!isEncryptableTerm(op, values[j])) continue
        pushTerm(values[j] as JsPlaintext, column, queryType, mappingFor(j))
      }
    }

    // Regular filters
    for (let i = 0; i < dbSpace.filters.length; i++) {
      const f = dbSpace.filters[i]
      if (!isEncryptedColumn(f.column, this.encryptedColumnNames)) continue

      const column = tableColumns[f.column]
      if (!column) continue

      if (f.op === 'in' && Array.isArray(f.value)) {
        collectInListTerms(
          f.op,
          f.value,
          column,
          mapFilterOpToQueryType(f.op),
          (inIndex) => ({ source: 'filter', filterIndex: i, inIndex }),
        )
      } else if (!isEncryptableTerm(f.op, f.value)) {
        // `is` predicate or null operand — forwarded unencrypted.
      } else {
        pushTerm(f.value as JsPlaintext, column, mapFilterOpToQueryType(f.op), {
          source: 'filter',
          filterIndex: i,
        })
      }
    }

    // Match filters
    for (let i = 0; i < dbSpace.matchFilters.length; i++) {
      const mf = dbSpace.matchFilters[i]
      for (const { column: colName, value } of mf.entries) {
        if (!isEncryptedColumn(colName, this.encryptedColumnNames)) continue
        // `match` carries no operator; equality is implied.
        if (!isEncryptableTerm('eq', value)) continue
        const column = tableColumns[colName]
        if (!column) continue

        pushTerm(value as JsPlaintext, column, 'equality', {
          source: 'match',
          matchIndex: i,
          column: colName,
        })
      }
    }

    // Not filters
    for (let i = 0; i < dbSpace.notFilters.length; i++) {
      const nf = dbSpace.notFilters[i]
      if (!isEncryptedColumn(nf.column, this.encryptedColumnNames)) continue
      if (!isEncryptableTerm(nf.op, nf.value)) continue
      const column = tableColumns[nf.column]
      if (!column) continue

      if (nf.op === 'in') {
        // A PostgREST list literal (`'(a,b)'`) cannot be encrypted element-wise,
        // and encrypting it whole matches nothing. Refuse it rather than emit a
        // filter that silently returns no rows.
        if (!Array.isArray(nf.value)) {
          throw new Error(
            `not("${nf.column}", "in", …) on an encrypted column requires an array of values, ` +
              `not a PostgREST list literal — each element must be encrypted separately`,
          )
        }
        collectInListTerms(
          nf.op,
          nf.value,
          column,
          mapFilterOpToQueryType(nf.op),
          (inIndex) => ({ source: 'not', notIndex: i, inIndex }),
        )
        continue
      }

      pushTerm(nf.value as JsPlaintext, column, mapFilterOpToQueryType(nf.op), {
        source: 'not',
        notIndex: i,
      })
    }

    // Or filters — conditions were parsed once, in `toDbSpace`. The string and
    // structured forms differ only in their `source` tag; the encryption rules,
    // including the `in`-list split below, are identical.
    for (let i = 0; i < dbSpace.orFilters.length; i++) {
      const of_ = dbSpace.orFilters[i]
      const source = of_.kind === 'string' ? 'or-string' : 'or-structured'

      for (let j = 0; j < of_.conditions.length; j++) {
        const cond = of_.conditions[j]
        if (!isEncryptedColumn(cond.column, this.encryptedColumnNames)) continue
        const column = tableColumns[cond.column]
        if (!column) continue

        // `queryTypeForOrOp`, not `mapFilterOpToQueryType`: an or-condition may
        // carry a raw PostgREST operator (`cs`), which is not a `FilterOp`.
        const queryType = this.queryTypeForOrOp(cond.op)
        const mappingFor = (inIndex?: number): TermMapping => ({
          source,
          orIndex: i,
          conditionIndex: j,
          inIndex,
        })

        if (cond.op === 'in' && Array.isArray(cond.value)) {
          collectInListTerms(cond.op, cond.value, column, queryType, mappingFor)
          continue
        }

        if (!isEncryptableTerm(cond.op, cond.value)) continue
        pushTerm(cond.value as JsPlaintext, column, queryType, mappingFor())
      }
    }

    // Raw filters
    for (let i = 0; i < dbSpace.rawFilters.length; i++) {
      const rf = dbSpace.rawFilters[i]
      if (!isEncryptedColumn(rf.column, this.encryptedColumnNames)) continue
      const column = tableColumns[rf.column]
      if (!column) continue

      if (rf.operator === 'in') {
        // Same contract as the `not(…, 'in', …)` path: a PostgREST list literal
        // (`'("a","b")'`) cannot be encrypted element-wise, and encrypting it
        // whole matches nothing. Refuse it rather than emit a filter that
        // silently returns no rows.
        if (!Array.isArray(rf.value)) {
          throw new Error(
            `filter("${rf.column}", "in", …) on an encrypted column requires an array of values, ` +
              `not a PostgREST list literal — each element must be encrypted separately`,
          )
        }
        collectInListTerms(
          'in',
          rf.value,
          column,
          this.queryTypeForRawOp(rf.operator),
          (inIndex) => ({ source: 'raw', rawIndex: i, inIndex }),
        )
        continue
      }

      if (!isEncryptableTerm(rf.operator, rf.value)) continue

      pushTerm(
        rf.value as JsPlaintext,
        column,
        this.queryTypeForRawOp(rf.operator),
        { source: 'raw', rawIndex: i },
      )
    }

    if (terms.length === 0) {
      return { encryptedValues: [], termMap: [] }
    }

    const encryptedValues = await this.encryptCollectedTerms(terms)
    return { encryptedValues, termMap }
  }

  /**
   * Encrypt every filter operand as a full storage envelope, serialized to jsonb
   * text for the PostgREST filter value.
   *
   * Terms are grouped by column and each group takes ONE `bulkEncrypt` crossing.
   * `in(col, [a, b, c])` collects one term per element (the list must never be
   * encrypted whole), so encrypting per term spent N ZeroKMS/FFI round-trips
   * where one would do. `bulkEncrypt` carries a single `{table, column}` for the
   * whole payload, so the grouping is mandatory, not an optimisation: one bulk
   * call over a mixed-column term array would stamp one column onto every
   * plaintext. Results are scattered back onto the terms' original indices,
   * which is the contract `termMap` downstream relies on.
   *
   * Mirrors `eql/v3/drizzle/operators.ts` `encryptOperands` — same batching
   * contract, same length assertion, same fallback. Kept separate because that
   * one encrypts a single-column operand list and returns `SQL[]`, while this
   * must group a multi-column term array and preserve positions.
   */
  protected async encryptCollectedTerms(
    terms: ScalarQueryTerm[],
  ): Promise<EncryptedQueryResult[]> {
    const groups = new Map<
      V3ColumnLike,
      { indices: number[]; values: ScalarQueryTerm['value'][] }
    >()
    terms.forEach((term, index) => {
      const column = this.assertTermQueryable(term)
      const group = groups.get(column) ?? { indices: [], values: [] }
      group.indices.push(index)
      group.values.push(term.value)
      groups.set(column, group)
    })

    const bulkEncrypt = this.encryptionClient.bulkEncrypt?.bind(
      this.encryptionClient,
    )
    // Each term becomes the `JSON.stringify`'d storage envelope — a `string`,
    // which is one arm of `EncryptedQueryResult`. PostgREST cannot cast a filter
    // value to the `eql_v3.query_<name>` twins, so v3 sends full envelopes,
    // serialized to jsonb text.
    const results = new Array<EncryptedQueryResult>(terms.length)

    await Promise.all(
      Array.from(groups, async ([column, { indices, values }]) => {
        const encrypted = bulkEncrypt
          ? await this.bulkEncryptGroup(bulkEncrypt, column, values)
          : await this.encryptGroupPerTerm(column, values)

        encrypted.forEach((envelope, i) => {
          results[indices[i]] = JSON.stringify(envelope)
        })
      }),
    )

    return results
  }

  /**
   * Validate a term's query type against its column's declared capabilities.
   * Pure validation: `encrypt`/`bulkEncrypt` never receive the query type. On
   * EQL 3.0.2+, free-text/JSON terms are rejected before this storage-encryption
   * path can place ciphertext in a GET URL.
   */
  private assertTermQueryable(term: ScalarQueryTerm): V3ColumnLike {
    const column = term.column as unknown as V3ColumnLike
    let queryType = term.queryType ?? 'equality'
    const capabilities = column.getQueryCapabilities()

    // The `cs` wire operator is capability-overloaded: bloom free-text on a
    // match/search TEXT column, encrypted ste_vec containment on a `types.Json`
    // DOCUMENT column. Both arrive here as `freeTextSearch` (contains/matches/
    // raw `cs` all map there); resolve to the capability the column actually
    // carries. The two are mutually exclusive by construction, so this can
    // never reinterpret a real free-text column.
    if (
      queryType === 'freeTextSearch' &&
      !capabilities.freeTextSearch &&
      capabilities.searchableJson
    ) {
      queryType = 'searchableJson'
    }

    if (
      queryType !== 'equality' &&
      queryType !== 'orderAndRange' &&
      queryType !== 'freeTextSearch' &&
      queryType !== 'searchableJson'
    ) {
      throw new Error(
        `[supabase v3]: query type "${queryType}" is not supported on EQL v3 columns`,
      )
    }

    if (!capabilities[queryType]) {
      throw new Error(
        `[supabase v3]: column "${column.getName()}" (${column.getEqlType()}) does not support ${queryType} queries — declare the column with a domain that carries that capability`,
      )
    }

    if (queryType === 'freeTextSearch' || queryType === 'searchableJson') {
      // This is the common boundary for every spelling that collects an
      // encrypted match/containment term: matches(), contains(), not(), raw
      // filter(), and both forms of or(). Method-level checks provide earlier
      // errors for the direct helpers, but cannot cover the raw filter paths on
      // their own.
      this.assertPostgrestCanQueryEncryptedOperator('filter', column.getName())
    }

    if (queryType === 'searchableJson') {
      // THE single enforced operand boundary for encrypted-JSON containment.
      // Terms reach this resolver from every spelling — contains(), raw
      // .filter(col,'cs',…), not(col,'contains'|'matches',…), and .or()
      // string/structured conditions — and only contains() has a method-level
      // guard. Without this check a raw string (e.g. a free-text term ported
      // from a text column, or an .or() condition value, which is always a
      // string) would be storage-encrypted as a JSON SCALAR and silently match
      // nothing; pre-#650 every such spelling failed loudly on capability.
      assertJsonContainmentOperand(column.getName(), term.value)
    }

    // Free-text (bloom) needle floor. A needle shorter than the tokenizer's
    // token_length produces NO tokens, so `bf @> '{}'` holds for every row and
    // the query would silently return (and the caller decrypt) the whole table
    // — a fail-open over-exposure. Reject it up front, mirroring the Drizzle v3
    // adapter (matchNeedleError) so both first-party surfaces guard identically.
    // JSON containment terms (searchableJson) are validated separately above.
    if (queryType === 'freeTextSearch') {
      const match = column.build().indexes?.match
      const reason = match ? matchNeedleError(term.value, match) : undefined
      if (reason) {
        throw new Error(
          `[supabase v3]: cannot search column "${column.getName()}": ${reason}`,
        )
      }
    }

    return column
  }

  private encryptionFailure(message: string, cause?: EncryptionError): never {
    logger.error(
      `Supabase: failed to encrypt query terms for table "${this.tableName}"`,
    )
    // Most callers pass the operation's own `EncryptionError`; the contract-
    // violation cases (bulk length mismatch, null envelope) have none, so
    // synthesize one — a broken query encryption is still an encryption failure,
    // and callers branch on `error.encryptionError` regardless.
    throw new EncryptionFailedError(
      `Failed to encrypt query terms: ${message}`,
      cause ?? { type: EncryptionErrorTypes.EncryptionError, message },
    )
  }

  /** One FFI crossing for a column's whole operand list. */
  private async bulkEncryptGroup(
    bulkEncrypt: NonNullable<EncryptionClient['bulkEncrypt']>,
    column: V3ColumnLike,
    values: ScalarQueryTerm['value'][],
  ): Promise<Array<Encrypted | null>> {
    const baseOp = bulkEncrypt(
      values.map((plaintext) => ({ plaintext })) as never,
      { column, table: this.table } as never,
    )
    const op = this.lockContext
      ? baseOp.withLockContext(this.lockContext)
      : baseOp
    if (this.auditConfig) op.audit(this.auditConfig)

    const result = await op
    if (result.failure)
      this.encryptionFailure(result.failure.message, result.failure)

    // `bulkEncrypt` is position-stable, so a length mismatch means the contract
    // was violated. Truncating instead would silently widen an `in` predicate
    // (or narrow a `not.in`) to whatever came back. `result.data` is now
    // `BulkEncryptedData` — `{ id?, data: Encrypted | null }[]` — not `unknown`.
    const encrypted = result.data
    if (encrypted.length !== values.length) {
      this.encryptionFailure(
        `bulk encryption returned ${encrypted.length} terms for ${values.length} values on column "${column.getName()}".`,
      )
    }
    return encrypted.map((term, i) => {
      // `BulkEncryptedData` types the element as `Encrypted | null`. A `null`
      // envelope here would be `JSON.stringify`'d to the literal string `"null"`
      // and sent as the filter operand — silently matching whatever `"null"`
      // encodes to rather than failing. A query term should never encrypt to a
      // null envelope, so treat it as a contract violation, not a value.
      if (term.data === null) {
        this.encryptionFailure(
          `bulk encryption returned a null envelope at position ${i} for column "${column.getName()}".`,
        )
      }
      return term.data
    })
  }

  /** Fallback for a client that predates `bulkEncrypt`. */
  private async encryptGroupPerTerm(
    column: V3ColumnLike,
    values: ScalarQueryTerm['value'][],
  ): Promise<Encrypted[]> {
    return Promise.all(
      values.map(async (value) => {
        const baseOp = this.encryptionClient.encrypt(value, {
          column,
          table: this.table,
        })
        const op = this.lockContext
          ? baseOp.withLockContext(this.lockContext)
          : baseOp
        if (this.auditConfig) op.audit(this.auditConfig)

        const result = await op
        if (result.failure) {
          this.encryptionFailure(result.failure.message, result.failure)
        }
        return result.data
      }),
    )
  }

  // ---------------------------------------------------------------------------
  // Phase boundary: property-space -> DB-space
  // ---------------------------------------------------------------------------

  /**
   * Translate every recorded column name from JS property space into DB space,
   * once. Downstream (`encryptFilterValues`, `applyFilters`,
   * `buildAndExecuteQuery`) consumes only the branded result, so a column can
   * no longer reach PostgREST untranslated — that is a compile error.
   *
   * Total: `filterColumnName`, `parseOrString`, and `resolveMutationOptions`
   * never throw, so this introduces no new early-throw point and cannot perturb
   * the order in which capability errors surface.
   *
   * Safe to run BEFORE encryption: `getColumnMap()`/`encryptedColumnNames` are
   * keyed by both property and DB name, so column lookup resolves identically
   * either side of the translation, and `tableColumns[prop]` is the very same
   * builder object as `tableColumns[db]`.
   */
  protected toDbSpace(): DbQuerySpace {
    return {
      filters: this.filters.map((f) => ({
        ...f,
        column: this.filterColumnName(f.column),
      })),
      matchFilters: this.matchFilters.map((mf) => ({
        entries: Object.entries(mf.query).map(([column, value]) => ({
          column: this.filterColumnName(column),
          value,
        })),
      })),
      notFilters: this.notFilters.map((nf) => ({
        ...nf,
        column: this.filterColumnName(nf.column),
      })),
      rawFilters: this.rawFilters.map((rf) => ({
        ...rf,
        column: this.filterColumnName(rf.column),
      })),
      orFilters: this.orFilters.map((of_) => this.orFilterToDbSpace(of_)),
      transforms: this.transforms.map((t) => this.transformToDbSpace(t)),
      mutation: this.mutation ? this.mutationToDbSpace(this.mutation) : null,
    }
  }

  /** Column names only. Which conditions were encrypted is never decided here:
   * it stays derived at apply time from the substitution maps, so this pass
   * never has to agree with the encryption predicate. The operator token is
   * settled later still, in `rebuildOrString`, where `contains` becomes `cs`
   * for encrypted and plaintext conditions alike. */
  private orFilterToDbSpace(of_: PendingOrFilter): DbPendingOrFilter {
    const toDbCondition = (c: PendingOrCondition): DbPendingOrCondition => ({
      ...c,
      column: this.filterColumnName(c.column),
    })

    if (of_.kind === 'string') {
      return {
        kind: 'string',
        original: of_.value,
        conditions: parseOrString(of_.value).map(toDbCondition),
        referencedTable: of_.referencedTable,
      }
    }
    return { kind: 'structured', conditions: of_.conditions.map(toDbCondition) }
  }

  /**
   * Encrypted ordering columns sort by their `op` term, not by the envelope.
   *
   * `order=col->op` is the one ordering expression PostgREST can emit that
   * reaches the OPE term. It must NOT leak into filters — those compare whole
   * envelopes through the `eql_v3.*` operators — which is why this is its own
   * seam rather than a change to `filterColumnName`.
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
  protected orderColumnName(column: string): DbName {
    const dbName = this.dbNameFor(column)
    const encrypted = this.v3Columns[column]
    if (!encrypted) return dbName as DbName

    return (
      this.columnSchemas[dbName]?.indexes?.ope ? `${dbName}->op` : dbName
    ) as DbName
  }

  private transformToDbSpace(t: TransformOp): DbTransformOp {
    switch (t.kind) {
      case 'order':
        return { ...t, column: this.orderColumnName(t.column) }
      // `returns` is in the union but never pushed (`returns()` is a cast).
      case 'limit':
      case 'range':
      case 'single':
      case 'maybeSingle':
      case 'csv':
      case 'abortSignal':
      case 'throwOnError':
      case 'returns':
        return t
      default: {
        const exhaustive: never = t
        return exhaustive
      }
    }
  }

  private mutationToDbSpace(m: MutationOp): DbMutationOp {
    switch (m.kind) {
      case 'insert':
      case 'upsert':
        return { ...m, options: this.resolveMutationOptions(m.options) }
      case 'update':
      case 'delete':
        return m // options carry no column names
      default: {
        const exhaustive: never = m
        return exhaustive
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Step 4: Build and execute real Supabase query
  // ---------------------------------------------------------------------------

  protected async buildAndExecuteQuery(
    encryptedMutation:
      | Record<string, unknown>
      | Record<string, unknown>[]
      | null,
    selectString: DbSelect | null,
    encryptedFilters: EncryptedFilterState,
    dbSpace: DbQuerySpace,
  ): Promise<RawSupabaseResult> {
    this.validateTransforms()

    let query: SupabaseQueryBuilder = this.supabaseClient.from(this.tableName)

    // Apply mutation — options already resolved to DB-space by `toDbSpace`.
    if (dbSpace.mutation) {
      switch (dbSpace.mutation.kind) {
        case 'insert':
          query = query.insert(encryptedMutation!, dbSpace.mutation.options)
          break
        case 'update':
          query = query.update(encryptedMutation!, dbSpace.mutation.options)
          break
        case 'upsert':
          query = query.upsert(encryptedMutation!, dbSpace.mutation.options)
          break
        case 'delete':
          query = query.delete(dbSpace.mutation.options)
          break
      }
    }

    // Apply select
    if (selectString !== null) {
      query = query.select(selectString, this.selectOptions)
    } else if (!this.mutation) {
      // Default select without explicit columns - shouldn't happen but fallback
      query = query.select('*' as DbSelect, this.selectOptions)
    }

    // Apply resolved filters
    query = this.applyFilters(query, encryptedFilters, dbSpace)

    // Apply transforms — column names already in DB-space.
    for (const t of dbSpace.transforms) {
      switch (t.kind) {
        case 'order':
          query = query.order(t.column, t.options)
          break
        case 'limit':
          query = query.limit(t.count, t.options)
          break
        case 'range':
          query = query.range(t.from, t.to, t.options)
          break
        case 'single':
          query = query.single()
          break
        case 'maybeSingle':
          query = query.maybeSingle()
          break
        case 'csv':
          query = query.csv()
          break
        case 'abortSignal':
          query = query.abortSignal(t.signal)
          break
        case 'throwOnError':
          query = query.throwOnError()
          break
      }
    }

    const result = (await query) as unknown as RawSupabaseResult
    return result
  }

  // ---------------------------------------------------------------------------
  // Apply filters with encrypted values substituted
  // ---------------------------------------------------------------------------

  protected applyFilters(
    query: SupabaseQueryBuilder,
    encryptedFilters: EncryptedFilterState,
    dbSpace: DbQuerySpace,
  ): SupabaseQueryBuilder {
    let q = query

    // Build lookup maps for quick access to encrypted values
    const filterValueMap = new Map<number, unknown>()
    const filterInMap = new Map<string, unknown>() // "filterIndex:inIndex" -> value
    const matchValueMap = new Map<string, unknown>() // "matchIndex:column" -> value
    const notValueMap = new Map<number, unknown>()
    const notInMap = new Map<string, unknown>() // "notIndex:inIndex" -> value
    const rawValueMap = new Map<number, unknown>()
    const rawInMap = new Map<string, unknown>() // "rawIndex:inIndex" -> value
    const orStringConditionMap = new Map<string, unknown>() // "orIndex:condIndex" -> value
    const orStructuredConditionMap = new Map<string, unknown>()

    for (let i = 0; i < encryptedFilters.termMap.length; i++) {
      const mapping = encryptedFilters.termMap[i]
      const encValue = encryptedFilters.encryptedValues[i]

      switch (mapping.source) {
        case 'filter':
          if (mapping.inIndex !== undefined) {
            filterInMap.set(
              `${mapping.filterIndex}:${mapping.inIndex}`,
              encValue,
            )
          } else {
            filterValueMap.set(mapping.filterIndex, encValue)
          }
          break
        case 'match':
          matchValueMap.set(`${mapping.matchIndex}:${mapping.column}`, encValue)
          break
        case 'not':
          if (mapping.inIndex !== undefined) {
            notInMap.set(`${mapping.notIndex}:${mapping.inIndex}`, encValue)
          } else {
            notValueMap.set(mapping.notIndex, encValue)
          }
          break
        case 'raw':
          if (mapping.inIndex !== undefined) {
            rawInMap.set(`${mapping.rawIndex}:${mapping.inIndex}`, encValue)
          } else {
            rawValueMap.set(mapping.rawIndex, encValue)
          }
          break
        // `inIndex` widens the key to address one element of an `in` list, so a
        // whole-condition value and a per-element value never collide.
        case 'or-string':
          orStringConditionMap.set(orKey(mapping), encValue)
          break
        case 'or-structured':
          orStructuredConditionMap.set(orKey(mapping), encValue)
          break
      }
    }

    // Apply regular filters
    for (let i = 0; i < dbSpace.filters.length; i++) {
      const f = dbSpace.filters[i]
      let value = f.value

      if (filterValueMap.has(i)) {
        value = filterValueMap.get(i)
      } else if (f.op === 'in' && Array.isArray(f.value)) {
        // Reconstruct array with encrypted values substituted
        value = f.value.map((v, j) => {
          const key = `${i}:${j}`
          return filterInMap.has(key) ? filterInMap.get(key) : v
        })
      }

      const column = f.column
      const wasEncrypted = filterValueMap.has(i)

      switch (f.op) {
        case 'eq':
          q = q.eq(column, value)
          break
        case 'neq':
          q = q.neq(column, value)
          break
        case 'gt':
          q = q.gt(column, value)
          break
        case 'gte':
          q = q.gte(column, value)
          break
        case 'lt':
          q = q.lt(column, value)
          break
        case 'lte':
          q = q.lte(column, value)
          break
        case 'like':
        case 'ilike':
          q = this.applyPatternFilter(q, column, f.op, value, wasEncrypted)
          break
        // `matches` (encrypted free-text) and `contains` (plaintext / encrypted
        // JSON) share the `cs`/`@>` wire operator; the operand encoding is the
        // same, so both emit through the one containment applier.
        case 'contains':
        case 'matches':
          q = this.applyContainsFilter(q, column, value, wasEncrypted)
          break
        case 'is':
          q = q.is(column, value)
          break
        case 'in':
          // `wasEncrypted` above is false for in-lists: their ciphertexts land
          // in `filterInMap`, keyed per element.
          q = this.applyInFilter(
            q,
            column,
            value as unknown[],
            Array.isArray(f.value) &&
              f.value.some((_, j) => filterInMap.has(`${i}:${j}`)),
          )
          break
      }
    }

    // Apply match filters
    for (let i = 0; i < dbSpace.matchFilters.length; i++) {
      const mf = dbSpace.matchFilters[i]
      const resolvedQuery: Record<string, unknown> = {}

      for (const { column: colName, value: originalValue } of mf.entries) {
        const key = `${i}:${colName}`
        resolvedQuery[colName] = matchValueMap.has(key)
          ? matchValueMap.get(key)
          : originalValue
      }

      q = q.match(resolvedQuery)
    }

    // Apply not filters
    for (let i = 0; i < dbSpace.notFilters.length; i++) {
      const nf = dbSpace.notFilters[i]

      if (nf.op === 'in' && Array.isArray(nf.value)) {
        const values = nf.value.map((v, j) =>
          notInMap.has(`${i}:${j}`) ? notInMap.get(`${i}:${j}`) : v,
        )
        q = q.not(nf.column, 'in', formatInListOperand(values))
        continue
      }

      const wasEncrypted = notValueMap.has(i)
      const value = wasEncrypted ? notValueMap.get(i) : nf.value

      // `contains` is a supabase-js METHOD name, not a PostgREST operator, and
      // `q.not()` interpolates its operand with `String(value)` — so an array
      // arrives brace-less and an object as `[object Object]`. Build the
      // containment literal ourselves and emit the `cs` token, exactly as the
      // `.or()` path does. A scalar (including the encrypted envelope, already
      // serialized) yields `null` and is forwarded untouched.
      if (nf.op === 'contains' || nf.op === 'matches') {
        const literal = formatContainmentOperand(value)
        q = q.not(nf.column, 'cs', literal ?? value)
        continue
      }

      q = q.not(nf.column, this.notFilterOperator(nf.op, wasEncrypted), value)
    }

    // Apply or filters
    for (let i = 0; i < dbSpace.orFilters.length; i++) {
      const of_ = dbSpace.orFilters[i]

      if (of_.kind === 'string') {
        // Already parsed (once) and translated by `toDbSpace`.
        const parsed = [...of_.conditions]

        for (let j = 0; j < parsed.length; j++) {
          const sub = substituteOrValue(orStringConditionMap, i, j, parsed[j])
          if (sub) {
            parsed[j] = { ...parsed[j], value: sub.value }
          }
        }

        // Rebuild whenever a condition REFERENCES an encrypted column — not
        // merely when a value was encrypted. An `is`/null operand on an
        // encrypted column encrypts nothing, so keying on "was a value
        // substituted" would send that condition down the verbatim path below
        // and forward the caller's JS property name to a DB that only knows the
        // column's real name. `toDbSpace` has already translated `parsed`.
        const referencesEncrypted = parsed.some((c) =>
          isEncryptedColumn(c.column, this.encryptedColumnNames),
        )

        if (referencesEncrypted) {
          q = q.or(rebuildOrString(parsed), {
            referencedTable: of_.referencedTable,
          })
        } else {
          // Every condition names a plaintext column, whose property name IS
          // its DB name — nothing to map. Forward the caller's ORIGINAL string
          // byte-for-byte: relied on for nested `and()` and quoted values that
          // `parseOrString`/`rebuildOrString` cannot round-trip.
          q = q.or(of_.original as DbFilterString, {
            referencedTable: of_.referencedTable,
          })
        }
      } else {
        // Structured: convert to string
        const conditions = of_.conditions.map((cond, j) => {
          const sub = substituteOrValue(orStructuredConditionMap, i, j, cond)
          return sub ? { ...cond, value: sub.value } : cond
        })

        q = q.or(rebuildOrString(conditions))
      }
    }

    // Apply raw filters
    for (let i = 0; i < dbSpace.rawFilters.length; i++) {
      const rf = dbSpace.rawFilters[i]

      // An encrypted `in` list was encrypted element-wise; reassemble it into
      // the quoted PostgREST list literal, exactly as the `not` path does. A
      // plaintext column keeps its operand untouched.
      if (
        rf.operator === 'in' &&
        Array.isArray(rf.value) &&
        isEncryptedColumn(rf.column, this.encryptedColumnNames)
      ) {
        const values = rf.value.map((v, j) =>
          rawInMap.has(`${i}:${j}`) ? rawInMap.get(`${i}:${j}`) : v,
        )
        q = q.filter(rf.column, rf.operator, formatInListOperand(values))
        continue
      }

      const value = rawValueMap.has(i) ? rawValueMap.get(i) : rf.value
      q = q.filter(rf.column, rf.operator, value)
    }

    return q
  }

  // ---------------------------------------------------------------------------
  // Dialect seams for native `eql_v3.*` domain columns.
  // ---------------------------------------------------------------------------

  /** Resolve a JS property name to its DB column name. `Object.hasOwn` guards
   * the inherited-member hazard described on {@link EncryptedTable.buildColumnKeyMap}. */
  private dbNameFor(name: string): string {
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
  protected filterColumnName(column: string): DbName {
    return this.dbNameFor(column) as DbName
  }

  /**
   * Resolve the column names carried by a mutation's options. `onConflict` is a
   * comma-separated column list, so it needs the same property→DB mapping as a
   * filter. Returns the original object when nothing changed.
   */
  protected resolveMutationOptions<
    O extends { onConflict?: string } | undefined,
  >(options: O): DbMutationOptions | undefined {
    if (!options?.onConflict) return options as DbMutationOptions | undefined
    const mapped = options.onConflict
      .split(',')
      .map((column) => this.filterColumnName(column.trim()))
      .join(',') as DbConflictList
    return (
      mapped === options.onConflict
        ? options
        : { ...options, onConflict: mapped }
    ) as DbMutationOptions
  }

  /**
   * `ORDER BY` on an OPE-backed column is supported; on every other encrypted
   * column it is rejected.
   *
   * A bare `ORDER BY col` IS wrong. The `*_ord` domains are
   * `CREATE DOMAIN … AS jsonb`, and the bundle declares no btree operator class
   * on any domain — it actively lints against one (`domain_opclass`), because an
   * opclass on a domain bypasses operator resolution. So the sort resolves
   * through jsonb's default `jsonb_cmp` and compares the envelope's keys in
   * storage order, starting at the random ciphertext `c`. No error, and a
   * stable, meaningless row order.
   *
   * But the correct sort key is reachable without a function call. `eql_v3.ord_term`
   * returns the domain's `op` term, and OPE is order-preserving by construction:
   * ordering by the term reproduces the plaintext order. PostgREST cannot emit
   * `ORDER BY eql_v3.ord_term(col)`, but it CAN emit a jsonb path —
   * `order=col->op.asc` — which selects exactly that term.
   *
   * So the guard is on the ordering FLAVOUR, not on encryption:
   *
   * - `ope` present → order by `col->op`. Every plain `_ord` domain, plus
   *   `text_ord` and `text_search`.
   * - `ore` present → reject. The `ob` term is an array of ORE blocks whose
   *   comparison needs the superuser-only opclass; a jsonb-path sort over it is
   *   meaningless.
   * - neither → reject. Storage-only, equality-only and match-only columns
   *   carry no ordering term to sort by.
   *
   * A column absent from {@link v3Columns} is a plaintext passthrough and orders
   * normally. This runtime guard is the only protection the untyped
   * (no-`schemas`) surface has.
   */
  protected validateTransforms(): void {
    for (const t of this.transforms) {
      if (t.kind !== 'order') continue
      const column = this.v3Columns[t.column]
      if (!column) continue

      const indexes = this.columnSchemas[column.getName()]?.indexes
      if (indexes?.ope) continue

      const reason = indexes?.ore
        ? 'its ORE ordering term (`ob`) needs the superuser-only ORE operator class, which PostgREST cannot reach through a jsonb path'
        : 'it carries no ordering term to sort by'

      throw new Error(
        `[supabase v3]: cannot order by encrypted column "${column.getName()}" (${column.getEqlType()}) — ${reason}. ` +
          'Order by a plaintext column, or use an OPE-backed ordering domain ' +
          '(`*_ord`, `text_ord`, `text_search`), or use the EQL v3 Drizzle integration.',
      )
    }
  }

  /**
   * Resolve a raw `.filter()` operator to the capability it exercises. A
   * supported v3 operand is a full storage envelope, so `queryType` never
   * selects a narrowing — it only tells {@link assertTermQueryable} which
   * capability to demand of the column.
   *
   * Unknown operators throw rather than silently defaulting to equality, which
   * would encrypt a term the column may not even be able to compare.
   */
  protected queryTypeForRawOp(operator: string): QueryTypeName {
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

  /**
   * Apply an `in` filter.
   *
   * A plaintext list goes to postgrest-js's `in()`, which quotes elements that
   * contain `,()`. An ENCRYPTED list cannot: every element is a
   * `JSON.stringify`d envelope, and `in()` wraps it in `"…"` without escaping
   * the quotes inside it, so PostgREST terminates the value at the envelope's
   * first `"`. Emit the operand ourselves and hand it to `filter()`, which
   * forwards it verbatim.
   */
  protected applyInFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    values: unknown[],
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    if (!wasEncrypted) return q.in(column, values)
    return q.filter(column, 'in', formatInListOperand(values))
  }

  /**
   * Apply a `like`/`ilike` filter. On an encrypted column `like`/`ilike` were
   * rewritten to `matches` at record time, so a `like`/`ilike` pending filter
   * only ever names a plaintext column, which keeps real SQL LIKE.
   */
  protected applyPatternFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    op: 'like' | 'ilike',
    value: unknown,
    _wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    return op === 'like'
      ? q.like(column, value as string)
      : q.ilike(column, value as string)
  }

  /**
   * Apply a `contains` filter. On a plaintext column this is PostgREST's native
   * jsonb/array containment. On an encrypted column `cs` resolves to the `@>`
   * operator the EQL bundle declares on the domain, backed by `eql_v3.matches`
   * (bloom-filter containment) — and the operand is the full storage envelope,
   * already `JSON.stringify`d, emitted via `filter(col, 'cs', json)` rather than
   * `q.contains` (postgrest-js's `contains` re-serializes a non-string operand).
   *
   * A structured plaintext operand is serialized here rather than by
   * postgrest-js, which joins array elements on `,` without quoting them — so
   * `['with,comma']` would reach Postgres as two elements. Scalars keep the
   * native path.
   */
  protected applyContainsFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    value: unknown,
    wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    if (wasEncrypted) {
      this.assertPostgrestCanQueryEncryptedOperator('filter', column)
      return q.filter(column, 'cs', value)
    }
    const literal = formatContainmentOperand(value)
    return literal !== null
      ? q.filter(column, 'cs', literal)
      : q.contains(column, value)
  }

  /**
   * The CipherStash query type for an `.or()` condition's operator on an
   * encrypted column. String-form conditions carry raw PostgREST operators
   * (`cs`), which are not {@link FilterOp}s.
   */
  protected queryTypeForOrOp(op: FilterOp): QueryTypeName {
    if (op === 'matches') return 'freeTextSearch'
    // Structured conditions may carry the `contains` METHOD spelling (the wire
    // token becomes `cs` in rebuildOrString). It maps to the same capability
    // gate as `cs`; on a JSON column the term resolver then re-types it to
    // searchableJson and validates the operand. selectorNe's IS-NULL-inclusive
    // or-form relies on this arm.
    if (op === 'contains') return 'freeTextSearch'
    return this.queryTypeForRawOp(op)
  }

  /**
   * The PostgREST operator to use for a `.not()` filter. Every {@link FilterOp}
   * except `contains` spells the same as its PostgREST operator; `contains` is
   * handled before this is reached, because it also needs its operand rewritten.
   */
  protected notFilterOperator(op: FilterOp, _wasEncrypted: boolean): string {
    return op
  }

  /**
   * Post-process a decrypted result row: rebuild `Date` values from the
   * encrypt-config `cast_as` (date/timestamp), mirroring the typed v3 client's
   * decrypt-model path.
   */
  protected postprocessDecryptedRow(
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    // Every key an encrypted column can appear under: the keys this select
    // actually produces (including caller-chosen aliases like `ts:createdAt`),
    // plus the static property and DB names as a fallback for paths that record
    // no select. Aliases win. Derived here from `this.selectColumns` (the row in
    // hand) rather than cached from `buildSelectString`, so a reused builder can
    // never postprocess a row with a previous operation's stale select map.
    const keyToDb: Record<string, string> = Object.assign(
      Object.create(null),
      this.selectColumns === null
        ? undefined
        : selectKeyToDbV3(this.selectColumns, this.propToDb),
    )
    for (const [property, dbName] of Object.entries(this.propToDb)) {
      keyToDb[property] ??= dbName
      keyToDb[dbName] ??= dbName
    }

    const out: Record<string, unknown> = { ...row }
    for (const [key, dbName] of Object.entries(keyToDb)) {
      const castAs = this.columnSchemas[dbName]?.cast_as
      if (!DATE_LIKE_CAST_SET.has(castAs as string)) continue
      const value = out[key]
      if (value == null || value instanceof Date) continue
      if (typeof value === 'string' || typeof value === 'number') {
        out[key] = new Date(value)
      }
    }
    return out
  }

  // ---------------------------------------------------------------------------
  // Step 5: Decrypt results
  // ---------------------------------------------------------------------------

  protected async decryptResults(
    result: RawSupabaseResult,
  ): Promise<EncryptedSupabaseResponse<T[]>> {
    // If there's an error from Supabase, pass it through
    if (result.error) {
      return {
        data: null,
        error: {
          message: result.error.message,
          details: result.error.details,
          hint: result.error.hint,
          code: result.error.code,
        },
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    // No data to decrypt
    if (result.data === null || result.data === undefined) {
      return {
        data: null,
        error: null,
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    // Determine if we need to decrypt
    const hasSelect = this.selectColumns !== null
    const hasMutationWithReturning = this.mutation !== null && hasSelect

    if (!hasSelect && !hasMutationWithReturning) {
      // No select means no data to decrypt (e.g., insert without .select())
      return {
        data: result.data as T[],
        error: null,
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    // Decrypt based on result mode
    if (this.resultMode === 'single' || this.resultMode === 'maybeSingle') {
      if (result.data === null) {
        return {
          data: null,
          error: null,
          count: result.count ?? null,
          status: result.status,
          statusText: result.statusText,
        }
      }

      // Single result — decrypt one model
      const baseDecryptOp = this.encryptionClient.decryptModel(
        result.data as Record<string, unknown>,
      )
      const decryptOp = this.lockContext
        ? baseDecryptOp.withLockContext(this.lockContext)
        : baseDecryptOp
      if (this.auditConfig) decryptOp.audit(this.auditConfig)

      const decrypted = await decryptOp
      if (decrypted.failure) {
        logger.error(
          `Supabase: failed to decrypt model for table "${this.tableName}"`,
        )

        throw new EncryptionFailedError(
          `Failed to decrypt model: ${decrypted.failure.message}`,
          decrypted.failure,
        )
      }

      return {
        data: this.postprocessDecryptedRow(
          decrypted.data as Record<string, unknown>,
        ) as unknown as T[],
        error: null,
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    // Array result — bulk decrypt
    const dataArray = result.data as Record<string, unknown>[]
    if (dataArray.length === 0) {
      return {
        data: [] as unknown as T[],
        error: null,
        count: result.count ?? null,
        status: result.status,
        statusText: result.statusText,
      }
    }

    const baseBulkDecryptOp = this.encryptionClient.bulkDecryptModels(dataArray)
    const bulkDecryptOp = this.lockContext
      ? baseBulkDecryptOp.withLockContext(this.lockContext)
      : baseBulkDecryptOp
    if (this.auditConfig) bulkDecryptOp.audit(this.auditConfig)

    const decrypted = await bulkDecryptOp
    if (decrypted.failure) {
      logger.error(
        `Supabase: failed to decrypt models for table "${this.tableName}"`,
      )

      throw new EncryptionFailedError(
        `Failed to decrypt models: ${decrypted.failure.message}`,
        decrypted.failure,
      )
    }

    return {
      data: decrypted.data.map((row) =>
        this.postprocessDecryptedRow(row as Record<string, unknown>),
      ) as unknown as T[],
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  protected getColumnMap(): Record<string, BuildableQueryColumn> {
    return this.v3Columns as unknown as Record<string, BuildableQueryColumn>
  }

  /** Warn once per (op, column) that a `like`/`ilike` was delegated to `matches`. */
  private static readonly warnedLikeDelegation = new Set<string>()

  /** True when `column` is one of this table's encrypted v3 columns. */
  private isEncryptedV3Column(column: string): boolean {
    return Boolean(this.v3Columns[column])
  }

  /** True when `column` is an encrypted `types.Json` document column. */
  private isSearchableJsonColumn(column: string): boolean {
    const builder: V3ColumnLike | undefined = this.v3Columns[column]
    return Boolean(builder?.getQueryCapabilities().searchableJson)
  }

  private assertPostgrestCanQueryEncryptedOperator(
    method: string,
    column: string,
  ): void {
    if (!this.queryDomainsRequired) return
    throw new Error(
      `[supabase v3]: ${method}() on encrypted column "${column}" is unavailable with EQL 3.0.2+: the SQL operator requires an eql_v3.query_* cast that PostgREST cannot express. Use the Drizzle or Prisma Next adapter, or a scoped SQL/RPC function.`,
    )
  }

  /**
   * Validate + reconstruct a selector needle: `('$.user.role', 'admin')` →
   * `{user: {role: 'admin'}}`. Shared by {@link selectorEq}/{@link selectorNe};
   * throws with column context for a non-JSON column, an invalid path, or a
   * non-scalar leaf.
   */
  private selectorNeedle(
    method: string,
    column: string,
    path: string,
    value: unknown,
  ): Record<string, unknown> {
    if (!this.isSearchableJsonColumn(column)) {
      throw new Error(
        `[supabase v3]: ${method}() requires an encrypted JSON (types.Json) column; "${column}" is not one.`,
      )
    }
    // Selector comparisons compare a scalar LEAF (null included in the shared
    // helper's rejection; eq/ne arm — `ordering: false`;
    // PostgREST cannot express selector ordering yet, see
    // cipherstash/encrypt-query-language#407).
    const leafReason = unsupportedLeafReason(value, false)
    if (leafReason) {
      throw new Error(
        `[supabase v3]: ${method}("${column}", "${path}", …): ${leafReason}`,
      )
    }
    // Stricter than the shared helper (whose Date/bigint arms serve the Drizzle
    // surface): a stored JsonDocument leaf is a JSON scalar, so a Date/bigint
    // needle could never match one — reject with the serialization steer
    // instead of running a query that structurally returns nothing.
    if (
      typeof value !== 'string' &&
      typeof value !== 'number' &&
      typeof value !== 'boolean'
    ) {
      throw new Error(
        `[supabase v3]: ${method}("${column}", "${path}", …): a JSON document leaf is a JSON scalar (string/number/boolean); got ${value instanceof Date ? 'a Date — pass date.toISOString() (or the stored form)' : typeof value}.`,
      )
    }
    let segments: string[]
    try {
      segments = parseSelectorSegments(path)
    } catch (err) {
      throw new Error(
        `[supabase v3]: ${method}("${column}", …): ${err instanceof Error ? err.message : String(err)}`,
      )
    }
    return reconstructSelectorDocument(segments, value)
  }

  /**
   * Reduce a SQL LIKE pattern to a fuzzy-match needle, or throw when it cannot be
   * approximated. Strips surrounding `%` (prefix/suffix wildcards, which fuzzy
   * matching subsumes); an internal `%` or any `_` is unapproximable. Warns once
   * per (op, column) that the delegation is approximate.
   */
  private likeNeedle(column: string, op: string, pattern: string): string {
    const needle = pattern.replace(/^%+/, '').replace(/%+$/, '')
    if (needle.includes('%') || pattern.includes('_')) {
      throw new Error(
        `[supabase v3]: "${op}" pattern "${pattern}" on encrypted column "${column}" has wildcards fuzzy free-text matching cannot honor (an internal "%" or any "_"). Use matches("${column}", term) with a literal search term.`,
      )
    }
    const key = `${op}:${column}`
    if (!EncryptedQueryBuilderImpl.warnedLikeDelegation.has(key)) {
      EncryptedQueryBuilderImpl.warnedLikeDelegation.add(key)
      logger.warn(
        `[supabase v3]: "${op}" on encrypted column "${column}" is delegated to matches() (fuzzy bloom token search). Results are APPROXIMATE — case-insensitive, one-sided (may false-positive), and wildcards/anchoring are not honored. Call matches() directly to make this explicit.`,
      )
    }
    return needle
  }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type TermMapping =
  | { source: 'filter'; filterIndex: number; inIndex?: number }
  | { source: 'match'; matchIndex: number; column: string }
  | { source: 'not'; notIndex: number; inIndex?: number }
  | { source: 'raw'; rawIndex: number; inIndex?: number }
  | {
      source: 'or-string'
      orIndex: number
      conditionIndex: number
      inIndex?: number
    }
  | {
      source: 'or-structured'
      orIndex: number
      conditionIndex: number
      inIndex?: number
    }

type EncryptedFilterState = {
  // `EncryptedQueryResult[]`, not `unknown[]` — `encryptCollectedTerms` returns
  // that type, and typing the field to match is what lets the restored envelope
  // type reach the use site (`encryptedValues[i]`) instead of widening back to
  // `unknown` at this boundary.
  encryptedValues: EncryptedQueryResult[]
  termMap: TermMapping[]
}

/** Key an `.or()` condition, or one element of its `in` list. */
function orKey(mapping: {
  orIndex: number
  conditionIndex: number
  inIndex?: number
}): string {
  const base = `${mapping.orIndex}:${mapping.conditionIndex}`
  return mapping.inIndex === undefined ? base : `${base}:${mapping.inIndex}`
}

/**
 * Substitute encrypted operands back into one `.or()` condition, returning
 * `undefined` when nothing was encrypted for it.
 *
 * An `in` list is reconstructed element-by-element so `formatOrValue` re-emits
 * the `(a,b)` list form. Substituting the array as a single value would collapse
 * it to one ciphertext that matches nothing.
 */
function substituteOrValue(
  map: Map<string, unknown>,
  orIndex: number,
  conditionIndex: number,
  cond: { op: FilterOp; value: unknown },
): { value: unknown } | undefined {
  const whole = orKey({ orIndex, conditionIndex })
  if (map.has(whole)) return { value: map.get(whole) }

  if (cond.op === 'in' && Array.isArray(cond.value)) {
    let substituted = false
    const value = cond.value.map((element, inIndex) => {
      const key = orKey({ orIndex, conditionIndex, inIndex })
      if (!map.has(key)) return element
      substituted = true
      return map.get(key)
    })
    if (substituted) return { value }
  }

  return undefined
}

type RawSupabaseResult = {
  data: unknown
  error: {
    message: string
    details?: string
    hint?: string
    code?: string
  } | null
  count?: number | null
  status: number
  statusText: string
}

export class EncryptionFailedError extends Error {
  public encryptionError: EncryptionError

  constructor(message: string, encryptionError: EncryptionError) {
    super(message)
    this.name = 'EncryptionFailedError'
    this.encryptionError = encryptionError
  }
}
