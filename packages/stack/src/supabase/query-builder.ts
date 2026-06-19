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
import type { ScalarQueryTerm } from '@/types'
import { logger } from '@/utils/logger'
import {
  addJsonbCasts,
  getEncryptedColumnNames,
  isEncryptedColumn,
  mapFilterOpToQueryType,
  parseOrString,
  rebuildOrString,
} from './helpers'
import type {
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
  private tableName: string
  private schema: EncryptedTable<EncryptedTableColumn>
  private encryptionClient: EncryptionClient
  private supabaseClient: SupabaseClientLike
  private encryptedColumnNames: string[]

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
  private lockContext: LockContext | null = null
  private auditConfig: AuditConfig | null = null

  constructor(
    tableName: string,
    schema: EncryptedTable<EncryptedTableColumn>,
    encryptionClient: EncryptionClient,
    supabaseClient: SupabaseClientLike,
  ) {
    this.tableName = tableName
    this.schema = schema
    this.encryptionClient = encryptionClient
    this.supabaseClient = supabaseClient
    this.encryptedColumnNames = getEncryptedColumnNames(schema)
  }

  // ---------------------------------------------------------------------------
  // Mutation methods
  // ---------------------------------------------------------------------------

  select(
    columns: string,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): this {
    if (columns === '*') {
      throw new Error(
        "encryptedSupabase does not support select('*'). Please list columns explicitly so that encrypted columns can be cast with ::jsonb.",
      )
    }
    this.selectColumns = columns
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

  like(column: string, pattern: string): this {
    this.filters.push({ op: 'like', column, value: pattern })
    return this
  }

  ilike(column: string, pattern: string): this {
    this.filters.push({ op: 'ilike', column, value: pattern })
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

  private async execute(): Promise<EncryptedSupabaseResponse<T[]>> {
    try {
      logger.debug(`Supabase encrypted query on table "${this.tableName}".`)

      // 1. Encrypt mutation data
      const encryptedMutation = await this.encryptMutationData()

      // 2. Build select string with ::jsonb casts
      const selectString = this.buildSelectString()

      // 3. Batch-encrypt filter values
      const encryptedFilters = await this.encryptFilterValues()

      // 4. Build and execute real Supabase query
      const result = await this.buildAndExecuteQuery(
        encryptedMutation,
        selectString,
        encryptedFilters,
      )

      // 5. Decrypt results
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

  private async encryptMutationData(): Promise<
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

      return bulkModelsToEncryptedPgComposites(result.data)
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

    return modelToEncryptedPgComposites(result.data)
  }

  // ---------------------------------------------------------------------------
  // Step 2: Build select string with casts
  // ---------------------------------------------------------------------------

  private buildSelectString(): string | null {
    if (this.selectColumns === null) return null
    return addJsonbCasts(this.selectColumns, this.encryptedColumnNames)
  }

  // ---------------------------------------------------------------------------
  // Step 3: Encrypt filter values
  // ---------------------------------------------------------------------------

  private async encryptFilterValues(): Promise<EncryptedFilterState> {
    // Collect all terms that need encryption
    const terms: ScalarQueryTerm[] = []
    const termMap: TermMapping[] = []

    const tableColumns = this.getColumnMap()

    // Regular filters
    for (let i = 0; i < this.filters.length; i++) {
      const f = this.filters[i]
      if (!isEncryptedColumn(f.column, this.encryptedColumnNames)) continue

      const column = tableColumns[f.column]
      if (!column) continue

      if (f.op === 'in' && Array.isArray(f.value)) {
        // For `in` filters, encrypt each value separately
        for (let j = 0; j < f.value.length; j++) {
          terms.push({
            value: f.value[j] as JsPlaintext,
            column,
            table: this.schema,
            queryType: mapFilterOpToQueryType(f.op),
            returnType: 'composite-literal',
          })
          termMap.push({ source: 'filter', filterIndex: i, inIndex: j })
        }
      } else if (f.op === 'is') {
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
    for (let i = 0; i < this.matchFilters.length; i++) {
      const mf = this.matchFilters[i]
      for (const [colName, value] of Object.entries(mf.query)) {
        if (!isEncryptedColumn(colName, this.encryptedColumnNames)) continue
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
    for (let i = 0; i < this.notFilters.length; i++) {
      const nf = this.notFilters[i]
      if (!isEncryptedColumn(nf.column, this.encryptedColumnNames)) continue
      const column = tableColumns[nf.column]
      if (!column) continue

      terms.push({
        value: nf.value as JsPlaintext,
        column,
        table: this.schema,
        queryType: mapFilterOpToQueryType(nf.op),
        returnType: 'composite-literal',
      })
      termMap.push({ source: 'not', notIndex: i })
    }

    // Or filters (string form parsed into conditions)
    for (let i = 0; i < this.orFilters.length; i++) {
      const of_ = this.orFilters[i]
      if (of_.kind === 'string') {
        const parsed = parseOrString(of_.value)
        for (let j = 0; j < parsed.length; j++) {
          const cond = parsed[j]
          if (!isEncryptedColumn(cond.column, this.encryptedColumnNames))
            continue
          const column = tableColumns[cond.column]
          if (!column) continue

          terms.push({
            value: cond.value as JsPlaintext,
            column,
            table: this.schema,
            queryType: mapFilterOpToQueryType(cond.op),
            returnType: 'composite-literal',
          })
          termMap.push({ source: 'or-string', orIndex: i, conditionIndex: j })
        }
      } else {
        for (let j = 0; j < of_.conditions.length; j++) {
          const cond = of_.conditions[j]
          if (!isEncryptedColumn(cond.column, this.encryptedColumnNames))
            continue
          const column = tableColumns[cond.column]
          if (!column) continue

          terms.push({
            value: cond.value as JsPlaintext,
            column,
            table: this.schema,
            queryType: mapFilterOpToQueryType(cond.op),
            returnType: 'composite-literal',
          })
          termMap.push({
            source: 'or-structured',
            orIndex: i,
            conditionIndex: j,
          })
        }
      }
    }

    // Raw filters
    for (let i = 0; i < this.rawFilters.length; i++) {
      const rf = this.rawFilters[i]
      if (!isEncryptedColumn(rf.column, this.encryptedColumnNames)) continue
      const column = tableColumns[rf.column]
      if (!column) continue

      terms.push({
        value: rf.value as JsPlaintext,
        column,
        table: this.schema,
        queryType: 'equality',
        returnType: 'composite-literal',
      })
      termMap.push({ source: 'raw', rawIndex: i })
    }

    if (terms.length === 0) {
      return { encryptedValues: [], termMap: [] }
    }

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

    return { encryptedValues: result.data, termMap }
  }

  // ---------------------------------------------------------------------------
  // Step 4: Build and execute real Supabase query
  // ---------------------------------------------------------------------------

  private async buildAndExecuteQuery(
    encryptedMutation:
      | Record<string, unknown>
      | Record<string, unknown>[]
      | null,
    selectString: string | null,
    encryptedFilters: EncryptedFilterState,
  ): Promise<RawSupabaseResult> {
    let query: SupabaseQueryBuilder = this.supabaseClient.from(this.tableName)

    // Apply mutation
    if (this.mutation) {
      switch (this.mutation.kind) {
        case 'insert':
          query = query.insert(encryptedMutation!, this.mutation.options)
          break
        case 'update':
          query = query.update(encryptedMutation!, this.mutation.options)
          break
        case 'upsert':
          query = query.upsert(encryptedMutation!, this.mutation.options)
          break
        case 'delete':
          query = query.delete(this.mutation.options)
          break
      }
    }

    // Apply select
    if (selectString !== null) {
      query = query.select(selectString, this.selectOptions)
    } else if (!this.mutation) {
      // Default select without explicit columns - shouldn't happen but fallback
      query = query.select('*', this.selectOptions)
    }

    // Apply resolved filters
    query = this.applyFilters(query, encryptedFilters)

    // Apply transforms
    for (const t of this.transforms) {
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

  private applyFilters(
    query: SupabaseQueryBuilder,
    encryptedFilters: EncryptedFilterState,
  ): SupabaseQueryBuilder {
    let q = query

    // Build lookup maps for quick access to encrypted values
    const filterValueMap = new Map<number, unknown>()
    const filterInMap = new Map<string, unknown>() // "filterIndex:inIndex" -> value
    const matchValueMap = new Map<string, unknown>() // "matchIndex:column" -> value
    const notValueMap = new Map<number, unknown>()
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
          notValueMap.set(mapping.notIndex, encValue)
          break
        case 'raw':
          rawValueMap.set(mapping.rawIndex, encValue)
          break
        case 'or-string':
          orStringConditionMap.set(
            `${mapping.orIndex}:${mapping.conditionIndex}`,
            encValue,
          )
          break
        case 'or-structured':
          orStructuredConditionMap.set(
            `${mapping.orIndex}:${mapping.conditionIndex}`,
            encValue,
          )
          break
      }
    }

    // Apply regular filters
    for (let i = 0; i < this.filters.length; i++) {
      const f = this.filters[i]
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

      switch (f.op) {
        case 'eq':
          q = q.eq(f.column, value)
          break
        case 'neq':
          q = q.neq(f.column, value)
          break
        case 'gt':
          q = q.gt(f.column, value)
          break
        case 'gte':
          q = q.gte(f.column, value)
          break
        case 'lt':
          q = q.lt(f.column, value)
          break
        case 'lte':
          q = q.lte(f.column, value)
          break
        case 'like':
          q = q.like(f.column, value as string)
          break
        case 'ilike':
          q = q.ilike(f.column, value as string)
          break
        case 'is':
          q = q.is(f.column, value)
          break
        case 'in':
          q = q.in(f.column, value as unknown[])
          break
      }
    }

    // Apply match filters
    for (let i = 0; i < this.matchFilters.length; i++) {
      const mf = this.matchFilters[i]
      const resolvedQuery: Record<string, unknown> = {}

      for (const [colName, originalValue] of Object.entries(mf.query)) {
        const key = `${i}:${colName}`
        resolvedQuery[colName] = matchValueMap.has(key)
          ? matchValueMap.get(key)
          : originalValue
      }

      q = q.match(resolvedQuery)
    }

    // Apply not filters
    for (let i = 0; i < this.notFilters.length; i++) {
      const nf = this.notFilters[i]
      const value = notValueMap.has(i) ? notValueMap.get(i) : nf.value
      q = q.not(nf.column, nf.op, value)
    }

    // Apply or filters
    for (let i = 0; i < this.orFilters.length; i++) {
      const of_ = this.orFilters[i]

      if (of_.kind === 'string') {
        const parsed = parseOrString(of_.value)
        let hasEncrypted = false

        for (let j = 0; j < parsed.length; j++) {
          const key = `${i}:${j}`
          if (orStringConditionMap.has(key)) {
            parsed[j] = { ...parsed[j], value: orStringConditionMap.get(key) }
            hasEncrypted = true
          }
        }

        if (hasEncrypted) {
          q = q.or(rebuildOrString(parsed), {
            referencedTable: of_.referencedTable,
          })
        } else {
          q = q.or(of_.value, { referencedTable: of_.referencedTable })
        }
      } else {
        // Structured: convert to string
        const conditions = of_.conditions.map((cond, j) => {
          const key = `${i}:${j}`
          if (orStructuredConditionMap.has(key)) {
            return { ...cond, value: orStructuredConditionMap.get(key) }
          }
          return cond
        })

        q = q.or(rebuildOrString(conditions))
      }
    }

    // Apply raw filters
    for (let i = 0; i < this.rawFilters.length; i++) {
      const rf = this.rawFilters[i]
      const value = rawValueMap.has(i) ? rawValueMap.get(i) : rf.value
      q = q.filter(rf.column, rf.operator, value)
    }

    return q
  }

  // ---------------------------------------------------------------------------
  // Step 5: Decrypt results
  // ---------------------------------------------------------------------------

  private async decryptResults(
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
        data: decrypted.data as unknown as T[],
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
      data: decrypted.data as unknown as T[],
      error: null,
      count: result.count ?? null,
      status: result.status,
      statusText: result.statusText,
    }
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  private getColumnMap(): Record<string, EncryptedColumn> {
    const map: Record<string, EncryptedColumn> = {}
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
  | { source: 'not'; notIndex: number }
  | { source: 'raw'; rawIndex: number }
  | { source: 'or-string'; orIndex: number; conditionIndex: number }
  | { source: 'or-structured'; orIndex: number; conditionIndex: number }

type EncryptedFilterState = {
  encryptedValues: unknown[]
  termMap: TermMapping[]
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

class EncryptionFailedError extends Error {
  public encryptionError: unknown

  constructor(message: string, encryptionError: unknown) {
    super(message)
    this.name = 'EncryptionFailedError'
    this.encryptionError = encryptionError
  }
}
