import type { JsPlaintext } from '@cipherstash/protect-ffi'
import type { EncryptionClient } from '@/encryption'
import {
  bulkModelsToEncryptedPgComposites,
  modelToEncryptedPgComposites,
} from '@/encryption/helpers'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { LockContext } from '@/identity'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import { EncryptedColumn } from '@/schema'
import type {
  BuildableQueryColumn,
  QueryTypeName,
  ScalarQueryTerm,
} from '@/types'
import { logger } from '@/utils/logger'
import {
  addJsonbCasts,
  formatInListOperand,
  getEncryptedColumnNames,
  isEncryptableTerm,
  isEncryptedColumn,
  mapFilterOpToQueryType,
  parseOrString,
  rebuildOrString,
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

/**
 * A deferred query builder that wraps Supabase's query builder to automatically
 * handle encryption and decryption of data.
 *
 * All chained operations are recorded synchronously. When the builder is awaited,
 * it encrypts mutation data, adds `::jsonb` casts, batch-encrypts filter values,
 * executes the real Supabase query, and decrypts results.
 */
export class EncryptedQueryBuilderImpl<
  T extends Record<string, unknown> = Record<string, unknown>,
> {
  protected tableName: string
  protected schema: EncryptedTable<EncryptedTableColumn>
  protected encryptionClient: EncryptionClient
  protected supabaseClient: SupabaseClientLike
  protected encryptedColumnNames: string[]
  /** All column names for the table (encrypted + plaintext), in ordinal order,
   * used to expand `select('*')`. `null` when the caller supplied no column
   * list (v2, or a v3 client that could not introspect). */
  protected allColumns: string[] | null = null

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
  protected lockContext: LockContext | null = null
  protected auditConfig: AuditConfig | null = null

  constructor(
    tableName: string,
    schema: EncryptedTable<EncryptedTableColumn>,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
    allColumns: string[] | null = null,
  ) {
    this.tableName = tableName
    this.schema = schema
    this.encryptionClient = encryptionClient
    this.supabaseClient = supabaseClient
    this.encryptedColumnNames = getEncryptedColumnNames(schema)
    this.allColumns = allColumns
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
   * Turn the introspected column list (DB names) into select tokens. The base
   * returns them unchanged — v2 never supplies a column list, so this is dead
   * for v2. The v3 dialect overrides it to emit JS property names, which is
   * what makes `addJsonbCastsV3` alias a renamed column back to its property
   * (`createdAt:created_at::jsonb`) rather than returning it under its DB name.
   */
  protected expandAllColumns(columns: string[]): string[] {
    return columns
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

  like(column: string, pattern: string): this {
    this.filters.push({ op: 'like', column, value: pattern })
    return this
  }

  ilike(column: string, pattern: string): this {
    this.filters.push({ op: 'ilike', column, value: pattern })
    return this
  }

  contains(column: string, value: unknown): this {
    this.filters.push({ op: 'contains', column, value })
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

  not(column: string, operator: string, value: unknown): this {
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

  withLockContext(lockContext: LockContext): this {
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

      const error: EncryptedSupabaseError = {
        message,
        encryptionError: undefined,
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
      const baseOp = this.encryptionClient.bulkEncryptModels(data, this.schema)
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
    const baseOp = this.encryptionClient.encryptModel(data, this.schema)
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
   * Encode an encrypted model for the Supabase request body. v2 wraps each
   * encrypted value in the `{ data: ... }` object expected by the
   * `eql_v2_encrypted` composite type. The v3 dialect overrides this — native
   * `eql_v3.*` domains are plain jsonb, so the raw payload is sent instead
   * (keyed by DB column name).
   */
  protected transformEncryptedMutationModel(
    model: Record<string, unknown>,
  ): Record<string, unknown> {
    return modelToEncryptedPgComposites(model)
  }

  protected transformEncryptedMutationModels(
    models: Record<string, unknown>[],
  ): Record<string, unknown>[] {
    return bulkModelsToEncryptedPgComposites(models)
  }

  // ---------------------------------------------------------------------------
  // Step 2: Build select string with casts
  // ---------------------------------------------------------------------------

  protected buildSelectString(): DbSelect | null {
    if (this.selectColumns === null) return null
    return addJsonbCasts(this.selectColumns, this.encryptedColumnNames)
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

    // Regular filters
    for (let i = 0; i < dbSpace.filters.length; i++) {
      const f = dbSpace.filters[i]
      if (!isEncryptedColumn(f.column, this.encryptedColumnNames)) continue

      const column = tableColumns[f.column]
      if (!column) continue

      if (f.op === 'in' && Array.isArray(f.value)) {
        // For `in` filters, encrypt each value separately. A null element is
        // SQL NULL and passes through; the applier restores it by index.
        for (let j = 0; j < f.value.length; j++) {
          if (!isEncryptableTerm(f.op, f.value[j])) continue
          terms.push({
            value: f.value[j] as JsPlaintext,
            column,
            table: this.schema,
            queryType: mapFilterOpToQueryType(f.op),
            returnType: 'composite-literal',
          })
          termMap.push({ source: 'filter', filterIndex: i, inIndex: j })
        }
      } else if (!isEncryptableTerm(f.op, f.value)) {
        // `is` predicate or null operand — forwarded unencrypted.
      } else {
        terms.push({
          value: f.value as JsPlaintext,
          column,
          table: this.schema,
          queryType: mapFilterOpToQueryType(f.op),
          returnType: 'composite-literal',
        })
        termMap.push({ source: 'filter', filterIndex: i })
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

        terms.push({
          value: value as JsPlaintext,
          column,
          table: this.schema,
          queryType: 'equality',
          returnType: 'composite-literal',
        })
        termMap.push({ source: 'match', matchIndex: i, column: colName })
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
        // Each element is its own ciphertext, exactly as the regular `in` and
        // `or(… .in. …)` paths do. Encrypting the whole list as one value
        // yields a filter that silently matches nothing.
        if (!Array.isArray(nf.value)) {
          throw new Error(
            `not("${nf.column}", "in", …) on an encrypted column requires an array of values, ` +
              `not a PostgREST list literal — each element must be encrypted separately`,
          )
        }
        for (let j = 0; j < nf.value.length; j++) {
          if (!isEncryptableTerm(nf.op, nf.value[j])) continue
          terms.push({
            value: nf.value[j] as JsPlaintext,
            column,
            table: this.schema,
            queryType: mapFilterOpToQueryType(nf.op),
            returnType: 'composite-literal',
          })
          termMap.push({ source: 'not', notIndex: i, inIndex: j })
        }
        continue
      }

      terms.push({
        value: nf.value as JsPlaintext,
        column,
        table: this.schema,
        queryType: mapFilterOpToQueryType(nf.op),
        returnType: 'composite-literal',
      })
      termMap.push({ source: 'not', notIndex: i })
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

        const pushTerm = (value: JsPlaintext, inIndex?: number) => {
          terms.push({
            value,
            column,
            table: this.schema,
            queryType: this.queryTypeForOrOp(cond.op),
            returnType: 'composite-literal',
          })
          termMap.push({ source, orIndex: i, conditionIndex: j, inIndex })
        }

        // Mirror the regular filter path: each element of an `in` list is its
        // own term. Encrypting the array as one value collapses `(a,b)` into a
        // single ciphertext that matches nothing.
        if (cond.op === 'in' && Array.isArray(cond.value)) {
          for (let k = 0; k < cond.value.length; k++) {
            if (!isEncryptableTerm(cond.op, cond.value[k])) continue
            pushTerm(cond.value[k] as JsPlaintext, k)
          }
          continue
        }

        if (!isEncryptableTerm(cond.op, cond.value)) continue
        pushTerm(cond.value as JsPlaintext)
      }
    }

    // Raw filters
    for (let i = 0; i < dbSpace.rawFilters.length; i++) {
      const rf = dbSpace.rawFilters[i]
      if (!isEncryptedColumn(rf.column, this.encryptedColumnNames)) continue
      if (!isEncryptableTerm(rf.operator, rf.value)) continue
      const column = tableColumns[rf.column]
      if (!column) continue

      terms.push({
        value: rf.value as JsPlaintext,
        column,
        table: this.schema,
        queryType: this.queryTypeForRawOp(rf.operator),
        returnType: 'composite-literal',
      })
      termMap.push({ source: 'raw', rawIndex: i })
    }

    if (terms.length === 0) {
      return { encryptedValues: [], termMap: [] }
    }

    const encryptedValues = await this.encryptCollectedTerms(terms)
    return { encryptedValues, termMap }
  }

  /**
   * Encrypt the collected filter terms, returning one encoded value per term
   * (in order). v2 batch-encrypts via `encryptQuery` with the
   * `composite-literal` return type — the `("json")` string the
   * `eql_v2_encrypted` composite operators compare. The v3 dialect overrides
   * this to produce full-envelope jsonb operands instead.
   */
  protected async encryptCollectedTerms(
    terms: ScalarQueryTerm[],
  ): Promise<unknown[]> {
    // Batch encrypt all terms in one call
    const baseOp = this.encryptionClient.encryptQuery(terms)
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

    return result.data
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
   * keyed by both property and DB name in v3 (and property == DB name in v2),
   * so column lookup resolves identically either side of the translation, and
   * `tableColumns[prop]` is the very same builder object as `tableColumns[db]`.
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

  private transformToDbSpace(t: TransformOp): DbTransformOp {
    switch (t.kind) {
      case 'order':
        return { ...t, column: this.filterColumnName(t.column) }
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
        // `resolveMutationOptions` returns the SAME reference when no column
        // needed renaming, which v2 relies on.
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
          rawValueMap.set(mapping.rawIndex, encValue)
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
        case 'contains':
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
          // byte-for-byte: v2 relies on this for nested `and()` and quoted
          // values that `parseOrString`/`rebuildOrString` cannot round-trip.
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
      const value = rawValueMap.has(i) ? rawValueMap.get(i) : rf.value
      q = q.filter(rf.column, rf.operator, value)
    }

    return q
  }

  // ---------------------------------------------------------------------------
  // Dialect seams — every default preserves the v2 behaviour byte-for-byte.
  // The v3 builder (see ./query-builder-v3) overrides these for native
  // `eql_v3.*` domain columns.
  // ---------------------------------------------------------------------------

  /**
   * Map a filter's column name to the DB column name PostgREST must see.
   * v2 schemas key columns by their DB name already, so this is the identity;
   * the v3 dialect resolves a JS property name to its DB name.
   *
   * This is the ONLY place a {@link DbName} is minted. The
   * {@link SupabaseQueryBuilder} seam accepts nothing else, so every column
   * name reaching PostgREST must pass through here.
   */
  protected filterColumnName(column: string): DbName {
    return column as DbName
  }

  /**
   * Resolve the column names carried by a mutation's options. `onConflict` is a
   * comma-separated column list, so it needs the same property→DB mapping as a
   * filter. Returns the original object when nothing changed, so v2 — where
   * {@link filterColumnName} is the identity — passes the caller's reference on
   * untouched.
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
   * Validate the accumulated transforms before the query is built. Called from
   * inside {@link execute}'s try, so a throw surfaces as a `status: 500` error
   * result (or rethrows under `throwOnError`), matching the filter-path
   * capability guard. v2 imposes no constraints.
   */
  protected validateTransforms(): void {}

  /**
   * The CipherStash query type to encrypt a raw `.filter(column, operator, …)`
   * term under. `operator` is an arbitrary PostgREST operator string, not a
   * {@link FilterOp}, so it cannot go through `mapFilterOpToQueryType`.
   *
   * v2 encrypts every raw filter as an equality term. That is wrong — a raw
   * `.filter('amount', 'gte', …)` wants an ORE term — but in v2 `queryType`
   * selects the `encryptQuery` narrowing, so correcting it changes the
   * ciphertext on the wire. Preserved verbatim here and tracked separately;
   * the v3 dialect, where `queryType` is only a capability gate, overrides it.
   */
  protected queryTypeForRawOp(_operator: string): QueryTypeName {
    return 'equality'
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
   * Apply a `like`/`ilike` filter. v2 relies on the `~~` operator defined on
   * `eql_v2_encrypted`; the v3 dialect overrides this for encrypted columns
   * because the `eql_v3.*` domains expose free-text match via `@>`
   * (PostgREST `cs`) rather than a LIKE operator.
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
   * jsonb/array containment. The v3 dialect overrides it for encrypted columns,
   * where `cs` resolves to the `@>` operator the EQL bundle declares on the
   * domain, backed by `eql_v3.contains` (bloom-filter containment).
   */
  protected applyContainsFilter(
    q: SupabaseQueryBuilder,
    column: DbName,
    value: unknown,
    _wasEncrypted: boolean,
  ): SupabaseQueryBuilder {
    return q.contains(column, value)
  }

  /**
   * The CipherStash query type for an `.or()` condition's operator on an
   * encrypted column. String-form conditions carry raw PostgREST operators
   * (`cs`), which are not {@link FilterOp}s; the v3 dialect maps those.
   */
  protected queryTypeForOrOp(op: FilterOp): QueryTypeName {
    return mapFilterOpToQueryType(op)
  }

  /**
   * The PostgREST operator to use for a `.not()` filter. The v3 dialect maps
   * `like`/`ilike` on encrypted columns to `cs` (see applyPatternFilter).
   */
  protected notFilterOperator(op: FilterOp, _wasEncrypted: boolean): string {
    return op
  }

  /**
   * Post-process a decrypted result row. The v3 dialect reconstructs `Date`
   * values from the encrypt-config `cast_as`; v2 returns rows unchanged.
   */
  protected postprocessDecryptedRow(
    row: Record<string, unknown>,
  ): Record<string, unknown> {
    return row
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
    const map: Record<string, BuildableQueryColumn> = {}
    const schema = this.schema as unknown as Record<string, unknown>

    for (const colName of this.encryptedColumnNames) {
      const col = schema[colName]
      if (col instanceof EncryptedColumn) {
        map[colName] = col
      }
    }

    return map
  }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type TermMapping =
  | { source: 'filter'; filterIndex: number; inIndex?: number }
  | { source: 'match'; matchIndex: number; column: string }
  | { source: 'not'; notIndex: number; inIndex?: number }
  | { source: 'raw'; rawIndex: number }
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
  encryptedValues: unknown[]
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
  public encryptionError: unknown

  constructor(message: string, encryptionError: unknown) {
    super(message)
    this.name = 'EncryptionFailedError'
    this.encryptionError = encryptionError
  }
}
