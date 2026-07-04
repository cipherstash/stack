import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { AnyV3Table, InferPlaintext, QueryTypesForColumn } from '@/eql/v3'
import type { EncryptionError } from '@/errors'
import type { LockContext } from '@/identity'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'

// ---------------------------------------------------------------------------
// Config & instance
// ---------------------------------------------------------------------------

export type EncryptedSupabaseConfig = {
  encryptionClient: EncryptionClient
  supabaseClient: SupabaseClientLike
}

export interface EncryptedSupabaseInstance {
  from<T extends Record<string, unknown> = Record<string, unknown>>(
    tableName: string,
    schema: EncryptedTable<EncryptedTableColumn>,
  ): EncryptedQueryBuilder<T>
}

// ---------------------------------------------------------------------------
// EQL v3 config & instance
// ---------------------------------------------------------------------------

export type EncryptedSupabaseV3Config = {
  encryptionClient: EncryptionClient
  supabaseClient: SupabaseClientLike
}

/**
 * The column builders declared on a v3 table, recovered from the table's
 * type-level `_columnType` brand.
 */
type V3ColumnsOfTable<Table> = Table extends {
  readonly _columnType: infer C
}
  ? C
  : never

/**
 * JS property names of a v3 table's storage-only columns — those whose domain
 * exposes no query capability (e.g. `types.Bool`, `types.Text`). Excluded from
 * the filterable keys so a filter on one is a type error, matching the runtime
 * guard in the v3 term encryption path.
 */
export type NonQueryableV3Keys<Table extends AnyV3Table> = {
  [K in Extract<keyof V3ColumnsOfTable<Table>, string>]: [
    QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>,
  ] extends [never]
    ? K
    : never
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * Row keys a v3 builder accepts in filter methods: every row key except the
 * table's storage-only encrypted columns. Plaintext (non-schema) columns pass
 * through untouched, exactly as in v2.
 */
export type V3FilterableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<Extract<keyof Row, string>, NonQueryableV3Keys<Table>>

/**
 * The v3 builder type: the shared {@link EncryptedQueryBuilder} surface with
 * filter methods narrowed to {@link V3FilterableKeys}.
 */
export type EncryptedQueryBuilderV3<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = EncryptedQueryBuilder<Row, V3FilterableKeys<Table, Row> & StringKeyOf<Row>>

export interface EncryptedSupabaseV3Instance {
  /**
   * `Row` defaults to exactly the table's inferred plaintext shape — NOT
   * widened with an index signature. Widening would collapse
   * {@link V3FilterableKeys} to `string` and silently disable the
   * storage-only-column filter guard. The trade-off: with the default `Row`,
   * plaintext passthrough columns (`id`, `created_at`, …) are not filterable
   * or insertable at the type level — pass an explicit `Row` that includes
   * them (`es.from<typeof users, UserRow>(…)`).
   */
  from<
    Table extends AnyV3Table,
    Row extends Record<string, unknown> = InferPlaintext<Table>,
  >(tableName: string, table: Table): EncryptedQueryBuilderV3<Table, Row>
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

export type EncryptedSupabaseResponse<T> = {
  data: T | null
  error: EncryptedSupabaseError | null
  count: number | null
  status: number
  statusText: string
}

export type EncryptedSupabaseError = {
  message: string
  details?: string
  hint?: string
  code?: string
  encryptionError?: EncryptionError
}

// ---------------------------------------------------------------------------
// Internal builder state
// ---------------------------------------------------------------------------

export type FilterOp =
  | 'eq'
  | 'neq'
  | 'like'
  | 'ilike'
  | 'in'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'is'

export type PendingFilter = {
  op: FilterOp
  column: string
  value: unknown
}

export type PendingOrFilter =
  | { kind: 'structured'; conditions: PendingOrCondition[] }
  | { kind: 'string'; value: string; referencedTable?: string }

export type PendingOrCondition = {
  column: string
  op: FilterOp
  value: unknown
}

export type PendingMatchFilter = {
  query: Record<string, unknown>
}

export type PendingNotFilter = {
  column: string
  op: FilterOp
  value: unknown
}

export type PendingRawFilter = {
  column: string
  operator: string
  value: unknown
}

export type TransformOp =
  | {
      kind: 'order'
      column: string
      options?: {
        ascending?: boolean
        nullsFirst?: boolean
        referencedTable?: string
        foreignTable?: string
      }
    }
  | {
      kind: 'limit'
      count: number
      options?: { referencedTable?: string; foreignTable?: string }
    }
  | {
      kind: 'range'
      from: number
      to: number
      options?: { referencedTable?: string; foreignTable?: string }
    }
  | { kind: 'single' }
  | { kind: 'maybeSingle' }
  | { kind: 'csv' }
  | { kind: 'abortSignal'; signal: AbortSignal }
  | { kind: 'throwOnError' }
  | { kind: 'returns' }

export type MutationOp =
  | {
      kind: 'insert'
      data: Record<string, unknown> | Record<string, unknown>[]
      options?: {
        count?: 'exact' | 'planned' | 'estimated'
        defaultToNull?: boolean
        onConflict?: string
      }
    }
  | {
      kind: 'update'
      data: Record<string, unknown>
      options?: { count?: 'exact' | 'planned' | 'estimated' }
    }
  | {
      kind: 'upsert'
      data: Record<string, unknown> | Record<string, unknown>[]
      options?: {
        count?: 'exact' | 'planned' | 'estimated'
        onConflict?: string
        ignoreDuplicates?: boolean
        defaultToNull?: boolean
      }
    }
  | { kind: 'delete'; options?: { count?: 'exact' | 'planned' | 'estimated' } }

export type ResultMode = 'array' | 'single' | 'maybeSingle'

// ---------------------------------------------------------------------------
// Minimal Supabase client shape (to avoid hard dependency)
// ---------------------------------------------------------------------------

export interface SupabaseQueryBuilder {
  select(
    columns?: string,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): SupabaseQueryBuilder
  insert(
    values: unknown,
    options?: Record<string, unknown>,
  ): SupabaseQueryBuilder
  update(
    values: unknown,
    options?: Record<string, unknown>,
  ): SupabaseQueryBuilder
  upsert(
    values: unknown,
    options?: Record<string, unknown>,
  ): SupabaseQueryBuilder
  delete(options?: Record<string, unknown>): SupabaseQueryBuilder
  eq(column: string, value: unknown): SupabaseQueryBuilder
  neq(column: string, value: unknown): SupabaseQueryBuilder
  gt(column: string, value: unknown): SupabaseQueryBuilder
  gte(column: string, value: unknown): SupabaseQueryBuilder
  lt(column: string, value: unknown): SupabaseQueryBuilder
  lte(column: string, value: unknown): SupabaseQueryBuilder
  like(column: string, value: unknown): SupabaseQueryBuilder
  ilike(column: string, value: unknown): SupabaseQueryBuilder
  is(column: string, value: unknown): SupabaseQueryBuilder
  in(column: string, values: unknown[]): SupabaseQueryBuilder
  filter(column: string, operator: string, value: unknown): SupabaseQueryBuilder
  not(column: string, operator: string, value: unknown): SupabaseQueryBuilder
  or(
    filters: string,
    options?: { referencedTable?: string; foreignTable?: string },
  ): SupabaseQueryBuilder
  match(query: Record<string, unknown>): SupabaseQueryBuilder
  order(column: string, options?: Record<string, unknown>): SupabaseQueryBuilder
  limit(count: number, options?: Record<string, unknown>): SupabaseQueryBuilder
  range(
    from: number,
    to: number,
    options?: Record<string, unknown>,
  ): SupabaseQueryBuilder
  single(): SupabaseQueryBuilder
  maybeSingle(): SupabaseQueryBuilder
  csv(): SupabaseQueryBuilder
  abortSignal(signal: AbortSignal): SupabaseQueryBuilder
  throwOnError(): SupabaseQueryBuilder
  returns<T>(): SupabaseQueryBuilder
  then(
    onfulfilled?: ((value: unknown) => unknown) | null,
    onrejected?: ((reason: unknown) => unknown) | null,
  ): Promise<unknown>
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export interface SupabaseClientLike {
  from(table: string): any
}

// ---------------------------------------------------------------------------
// Re-export for convenience
// ---------------------------------------------------------------------------

export type { EncryptionClient } from '@/encryption'
export type { AuditConfig } from '@/encryption/operations/base-operation'
export type { LockContext } from '@/identity'
export type {
  EncryptedColumn,
  EncryptedTable,
  EncryptedTableColumn,
} from '@/schema'

// ---------------------------------------------------------------------------
// Forward declaration for query builder (avoids circular)
// ---------------------------------------------------------------------------

/** Helper to extract string keys from T */
type StringKeyOf<T> = Extract<keyof T, string>

export interface EncryptedQueryBuilder<
  T extends Record<string, unknown> = Record<string, unknown>,
  FK extends StringKeyOf<T> = StringKeyOf<T>,
> extends PromiseLike<EncryptedSupabaseResponse<T[]>> {
  select(
    columns: string,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): EncryptedQueryBuilder<T, FK>
  insert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      defaultToNull?: boolean
      onConflict?: string
    },
  ): EncryptedQueryBuilder<T, FK>
  update(
    data: Partial<T>,
    options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): EncryptedQueryBuilder<T, FK>
  upsert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      onConflict?: string
      ignoreDuplicates?: boolean
      defaultToNull?: boolean
    },
  ): EncryptedQueryBuilder<T, FK>
  delete(options?: {
    count?: 'exact' | 'planned' | 'estimated'
  }): EncryptedQueryBuilder<T, FK>
  eq<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  neq<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  gt<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  gte<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  lt<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  lte<K extends FK>(column: K, value: T[K]): EncryptedQueryBuilder<T, FK>
  like<K extends FK>(column: K, pattern: string): EncryptedQueryBuilder<T, FK>
  ilike<K extends FK>(column: K, pattern: string): EncryptedQueryBuilder<T, FK>
  is<K extends FK>(
    column: K,
    value: null | boolean,
  ): EncryptedQueryBuilder<T, FK>
  in<K extends FK>(column: K, values: T[K][]): EncryptedQueryBuilder<T, FK>
  filter<K extends FK>(
    column: K,
    operator: string,
    value: T[K],
  ): EncryptedQueryBuilder<T, FK>
  not<K extends FK>(
    column: K,
    operator: string,
    value: T[K],
  ): EncryptedQueryBuilder<T, FK>
  or(
    filters: string,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T, FK>
  or(
    conditions: PendingOrCondition[],
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T, FK>
  match(query: Partial<Pick<T, FK>>): EncryptedQueryBuilder<T, FK>
  order<K extends StringKeyOf<T>>(
    column: K,
    options?: {
      ascending?: boolean
      nullsFirst?: boolean
      referencedTable?: string
      foreignTable?: string
    },
  ): EncryptedQueryBuilder<T, FK>
  limit(
    count: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T, FK>
  range(
    from: number,
    to: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T, FK>
  single(): EncryptedQueryBuilder<T, FK>
  maybeSingle(): EncryptedQueryBuilder<T, FK>
  csv(): EncryptedQueryBuilder<T, FK>
  abortSignal(signal: AbortSignal): EncryptedQueryBuilder<T, FK>
  throwOnError(): EncryptedQueryBuilder<T, FK>
  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilder<U>
  withLockContext(lockContext: LockContext): EncryptedQueryBuilder<T, FK>
  audit(config: AuditConfig): EncryptedQueryBuilder<T, FK>
}
