import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
import type { AnyV3Table, InferPlaintext, QueryTypesForColumn } from '@/eql/v3'
import type { EncryptionError } from '@/errors'
import type { LockContext } from '@/identity'
import type { EncryptedTable, EncryptedTableColumn } from '@/schema'
import type { ClientConfig } from '@/types'
import type { V3Schemas } from './schema-builder'

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

export type { V3Schemas }

/**
 * Options for {@link import('./index').encryptedSupabaseV3}.
 *
 * @typeParam S - declared v3 tables. When present, `from()` is constrained to
 *   the declared table names and returns typed builders, and the tables are
 *   verified against the database at construction.
 */
export type EncryptedSupabaseV3Options<
  S extends V3Schemas | undefined = undefined,
> = {
  /** Postgres connection string for introspection. Defaults to
   * `process.env.DATABASE_URL`. */
  databaseUrl?: string
  /** Passed through to the encryption client (`eqlVersion` is forced to 3). */
  config?: ClientConfig
  /**
   * Optional declared v3 tables, keyed by table name (each record key MUST
   * equal its table's `tableName`). Declaring a table adds compile-time types
   * and startup verification; undeclared tables behave exactly as with no
   * `schemas`.
   *
   * ASYMMETRY: the `include_original: false` substring-`like` behaviour of a
   * `text_search` column can only be honoured on a DECLARED column. A substring
   * `like` against an UNDECLARED `text_search` column will not match, because
   * the synthesized default `include_original: true` puts the whole pattern into
   * the bloom filter as an extra token.
   */
  schemas?: S
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

/** Untyped instance (no `schemas`): rows default to `Record<string, unknown>`
 * and `from` accepts any table name. */
export interface EncryptedSupabaseV3Instance {
  from<Row extends Record<string, unknown> = Record<string, unknown>>(
    tableName: string,
  ): EncryptedQueryBuilder<Row>
}

/** Typed instance (with `schemas: S`): a declared table name resolves to the
 * narrowed v3 builder; any other table name falls back to the untyped surface.
 *
 * The fallback overload is REQUIRED, not a convenience. The design spec
 * promises a gradient — "declare one table, leave the rest introspected;
 * undeclared tables behave exactly as they would with no `schemas` at all".
 * With only the `keyof S` overload, `schemas: { users }` makes `from('orders')`
 * a compile error even though `orders` was introspected and works perfectly at
 * runtime. Declaring one table would silently make every other table
 * unreachable.
 *
 * Overload order matters: the literal-constrained signature is declared first,
 * so TypeScript prefers it whenever the argument is a declared key and only
 * falls through to `string` otherwise. */
export interface TypedEncryptedSupabaseV3Instance<S extends V3Schemas> {
  from<K extends keyof S & string>(
    table: K,
  ): EncryptedQueryBuilderV3<S[K], InferPlaintext<S[K]>>
  from<Row extends Record<string, unknown> = Record<string, unknown>>(
    table: string,
  ): EncryptedQueryBuilder<Row>
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
  /** `columns` defaults to `'*'`, matching supabase-js. A `'*'` select expands
   * to the introspected column list when one is available (v3), and otherwise
   * throws — v2 has no column list to cast, so `select()` and `select('*')`
   * both throw there. */
  select(
    columns?: string,
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
  match(query: Partial<T>): EncryptedQueryBuilder<T, FK>
  // `FK`, not `StringKeyOf<T>`: ordering an encrypted column relies on its ORE
  // index, which a storage-only domain lacks. `FK` defaults to `StringKeyOf<T>`,
  // so the v2 surface is unchanged; only the v3 typed instance narrows.
  order<K extends FK>(
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
