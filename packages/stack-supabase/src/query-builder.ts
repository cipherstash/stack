import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import {
  logger,
  parseSelectorSegments,
  reconstructSelectorDocument,
  unsupportedLeafReason,
} from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import type { LockContextInput } from '@cipherstash/stack/identity'
import { ColumnMap } from './column-map'
import { addJsonbCastsV3 } from './helpers'
import { toDbSpace } from './query-dbspace'
import {
  assertJsonContainmentOperand,
  assertPostgrestCanQueryEncryptedOperator,
  type EncryptedFilterState,
  type EncryptionContext,
  EncryptionFailedError,
  encryptFilterValues,
} from './query-encrypt'
import { applyFilters } from './query-filters'
import { encryptMutationData } from './query-mutation'
import {
  type DecryptContext,
  decryptResults,
  type RawSupabaseResult,
} from './query-results'
import type {
  DbQuerySpace,
  DbSelect,
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
  RecordedOps,
  ResultMode,
  SupabaseClientLike,
  SupabaseQueryBuilder,
  TransformOp,
} from './types'

export { EncryptionFailedError } from './query-encrypt'

/** Warn once per (op, column) that a `like`/`ilike` was delegated to `matches`. */
const warnedLikeDelegation = new Set<string>()

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
 * `cast_as`, mirroring the typed v3 client. This builder authors and reads EQL
 * v3 only: legacy `eql_v2_encrypted` columns are not recognised by introspection,
 * so they never enter the encrypt config and are returned as untouched
 * passthroughs. Decrypt v2 data with the core `@cipherstash/stack` client.
 *
 * The pipeline is split across sibling modules — `./column-map` (name and
 * capability resolution), `./query-encrypt` (mutation data and filter terms),
 * `./query-dbspace` (property → DB space), `./query-filters` (operand
 * substitution), `./query-results` (decryption) — and orchestrated by
 * {@link execute} below.
 */
export class EncryptedQueryBuilderImpl<
  T extends Record<string, unknown> = Record<string, unknown>,
  /** The shape this builder awaits to. `T[]` normally; narrowed to `T` by
   * {@link single}/{@link maybeSingle}, which return ONE row. Carried as a
   * parameter so the promise cannot keep advertising `T[]` after the runtime
   * has been switched to single-row mode. */
  TData = T[],
> {
  private tableName: string
  private table: AnyV3Table
  private encryptionClient: EncryptionClient
  private supabaseClient: SupabaseClientLike
  /** Name and capability resolution for this table's columns. */
  private columns: ColumnMap
  /** All column names for the table (encrypted + plaintext), in ordinal order,
   * used to expand `select('*')`. `null` when the caller supplied no column
   * list (a v3 client that could not introspect). */
  private allColumns: string[] | null = null
  /** EQL 3.0.2+ requires query-domain casts PostgREST cannot express. */
  private queryDomainsRequired: boolean

  // Recorded operations
  private mutation: MutationOp | null = null
  private selectColumns: string | null = null
  private selectOptions:
    | { head?: boolean; count?: 'exact' | 'planned' | 'estimated' }
    | undefined = undefined
  private filters: PendingFilter[] = []
  private orFilters: PendingOrFilter[] = []
  private matchFilters: PendingMatchFilter[] = []
  private notFilters: PendingNotFilter[] = []
  private rawFilters: PendingRawFilter[] = []
  private transforms: TransformOp[] = []
  private resultMode: ResultMode = 'array'
  private shouldThrowOnError = false

  // Encryption-specific state
  private lockContext: LockContextInput | null = null
  private auditConfig: AuditConfig | null = null

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
    this.columns = new ColumnMap(tableName, table, allColumns)
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
      this.selectColumns = this.columns
        .expandAllColumns(this.allColumns)
        .join(', ')
    } else {
      this.selectColumns = columns
    }
    this.selectOptions = options
    return this
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
    if (!this.columns.isEncryptedV3Column(column)) {
      this.filters.push({ op: 'like', column, value: pattern })
      return this
    }
    return this.matches(column, this.likeNeedle(column, 'like', pattern))
  }

  ilike(column: string, pattern: string): this {
    if (!this.columns.isEncryptedV3Column(column)) {
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
    if (this.columns.isSearchableJsonColumn(column)) {
      this.assertPostgrestCanQueryEncrypted('contains', column)
      // Same validator the term resolver enforces — failing here just surfaces
      // the error at the call site instead of at execution.
      assertJsonContainmentOperand(column, value)
      this.filters.push({ op: 'contains', column, value })
      return this
    }
    if (this.columns.isEncryptedV3Column(column)) {
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
    if (this.columns.isSearchableJsonColumn(column)) {
      throw new Error(
        `[supabase v3]: matches() is encrypted free-text search and does not apply to encrypted JSON column "${column}". Use contains("${column}", subDocument) or selectorEq("${column}", path, value).`,
      )
    }
    if (!this.columns.isEncryptedV3Column(column)) {
      throw new Error(
        `[supabase v3]: matches() is encrypted free-text search and requires an encrypted column; "${column}" is not one. Use contains() for native containment.`,
      )
    }
    this.assertPostgrestCanQueryEncrypted('matches', column)
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
      this.columns.isEncryptedV3Column(column) &&
      !this.columns.isSearchableJsonColumn(column)
    ) {
      throw new Error(
        `[supabase v3]: not("${column}", 'contains', …) does not apply to encrypted column "${column}" — that is fuzzy free-text matching, not containment. Use not("${column}", 'matches', …) or the raw 'cs' operator.`,
      )
    }
    // Mirror of the matches() guard: a `matches` spelling on a JSON column
    // would otherwise resolve to containment (the two share the `cs` wire op),
    // silently negating an EXACT operation under a name that promises FUZZY.
    if (operator === 'matches' && this.columns.isSearchableJsonColumn(column)) {
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
    this.assertPostgrestCanQueryEncrypted('selectorEq', column)
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
    this.assertPostgrestCanQueryEncrypted('selectorNe', column)
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

  single(): EncryptedQueryBuilderImpl<T, T> {
    this.resultMode = 'single'
    this.transforms.push({ kind: 'single' })
    // Type-level narrowing only; builder state is preserved. `TData` appears in
    // `then`/`execute` return positions, so the two instantiations are not
    // mutually assignable and `this` cannot be re-typed without an assertion.
    return this as unknown as EncryptedQueryBuilderImpl<T, T>
  }

  maybeSingle(): EncryptedQueryBuilderImpl<T, T> {
    this.resultMode = 'maybeSingle'
    this.transforms.push({ kind: 'maybeSingle' })
    return this as unknown as EncryptedQueryBuilderImpl<T, T>
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

  /** Re-type the ROW. The awaited SHAPE is preserved: called after
   * `single()`/`maybeSingle()` this still awaits one row, not `U[]`. */
  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilderImpl<
    U,
    TData extends readonly unknown[] ? U[] : U
  > {
    // Type-level cast only; builder state is preserved
    return this as unknown as EncryptedQueryBuilderImpl<
      U,
      TData extends readonly unknown[] ? U[] : U
    >
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

  then<TResult1 = EncryptedSupabaseResponse<TData>, TResult2 = never>(
    onfulfilled?:
      | ((
          value: EncryptedSupabaseResponse<TData>,
        ) => TResult1 | PromiseLike<TResult1>)
      | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected)
  }

  // ---------------------------------------------------------------------------
  // Core execution
  // ---------------------------------------------------------------------------

  private async execute(): Promise<EncryptedSupabaseResponse<TData>> {
    try {
      logger.debug(`Supabase encrypted query on table "${this.tableName}".`)

      const ctx = this.encryptionContext()

      // 1. Encrypt mutation data
      const encryptedMutation = await encryptMutationData(this.mutation, ctx)

      // 2. Build select string with ::jsonb casts
      const selectString = this.buildSelectString()

      // 3. Translate every recorded column name into DB-space, once.
      const dbSpace = toDbSpace(this.recordedOps(), this.columns)

      // 4. Batch-encrypt filter values
      const encryptedFilters = await encryptFilterValues(dbSpace, ctx)

      // 5. Build and execute real Supabase query
      const result = await this.buildAndExecuteQuery(
        encryptedMutation,
        selectString,
        encryptedFilters,
        dbSpace,
      )

      // 6. Decrypt results
      return await decryptResults<T, TData>(result, {
        ...ctx,
        selectColumns: this.selectColumns,
        resultMode: this.resultMode,
        hasMutation: this.mutation !== null,
      } satisfies DecryptContext)
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

  /** The shared slice of builder state every encrypt/decrypt step needs. Built
   * per `execute()`, so `lockContext`/`auditConfig` are read at execution time. */
  private encryptionContext(): EncryptionContext {
    return {
      tableName: this.tableName,
      table: this.table,
      encryptionClient: this.encryptionClient,
      lockContext: this.lockContext,
      auditConfig: this.auditConfig,
      columns: this.columns,
      queryDomainsRequired: this.queryDomainsRequired,
    }
  }

  /** The recorded query in property space, for `toDbSpace`. */
  private recordedOps(): RecordedOps {
    return {
      filters: this.filters,
      matchFilters: this.matchFilters,
      notFilters: this.notFilters,
      rawFilters: this.rawFilters,
      orFilters: this.orFilters,
      transforms: this.transforms,
      mutation: this.mutation,
    }
  }

  // ---------------------------------------------------------------------------
  // Step 2: Build select string with casts
  // ---------------------------------------------------------------------------

  private buildSelectString(): DbSelect | null {
    if (this.selectColumns === null) return null
    return addJsonbCastsV3(this.selectColumns, this.columns.propToDb)
  }

  // ---------------------------------------------------------------------------
  // Step 5: Build and execute real Supabase query
  // ---------------------------------------------------------------------------

  private async buildAndExecuteQuery(
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
    query = applyFilters(
      query,
      encryptedFilters,
      dbSpace,
      this.columns,
      this.queryDomainsRequired,
    )

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
   * A column with no encrypted builder is a plaintext passthrough and orders
   * normally. This runtime guard is the only protection the untyped
   * (no-`schemas`) surface has.
   */
  private validateTransforms(): void {
    for (const t of this.transforms) {
      if (t.kind !== 'order') continue
      const column = this.columns.encryptedColumn(t.column)
      if (!column) continue

      const indexes = this.columns.schemaFor(column.getName())?.indexes
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

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private assertPostgrestCanQueryEncrypted(
    method: string,
    column: string,
  ): void {
    assertPostgrestCanQueryEncryptedOperator(
      this.queryDomainsRequired,
      method,
      column,
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
    if (!this.columns.isSearchableJsonColumn(column)) {
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
    if (!warnedLikeDelegation.has(key)) {
      warnedLikeDelegation.add(key)
      logger.warn(
        `[supabase v3]: "${op}" on encrypted column "${column}" is delegated to matches() (fuzzy bloom token search). Results are APPROXIMATE — case-insensitive, one-sided (may false-positive), and wildcards/anchoring are not honored. Call matches() directly to make this explicit.`,
      )
    }
    return needle
  }
}
