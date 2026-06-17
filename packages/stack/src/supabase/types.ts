import type { EncryptionClient } from '@/encryption'
import type { AuditConfig } from '@/encryption/operations/base-operation'
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
> extends PromiseLike<EncryptedSupabaseResponse<T[]>> {
  select(
    columns: string,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): EncryptedQueryBuilder<T>
  insert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      defaultToNull?: boolean
      onConflict?: string
    },
  ): EncryptedQueryBuilder<T>
  update(
    data: Partial<T>,
    options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): EncryptedQueryBuilder<T>
  upsert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      onConflict?: string
      ignoreDuplicates?: boolean
      defaultToNull?: boolean
    },
  ): EncryptedQueryBuilder<T>
  delete(options?: {
    count?: 'exact' | 'planned' | 'estimated'
  }): EncryptedQueryBuilder<T>
  eq<K extends StringKeyOf<T>>(column: K, value: T[K]): EncryptedQueryBuilder<T>
  neq<K extends StringKeyOf<T>>(
    column: K,
    value: T[K],
  ): EncryptedQueryBuilder<T>
  gt<K extends StringKeyOf<T>>(column: K, value: T[K]): EncryptedQueryBuilder<T>
  gte<K extends StringKeyOf<T>>(
    column: K,
    value: T[K],
  ): EncryptedQueryBuilder<T>
  lt<K extends StringKeyOf<T>>(column: K, value: T[K]): EncryptedQueryBuilder<T>
  lte<K extends StringKeyOf<T>>(
    column: K,
    value: T[K],
  ): EncryptedQueryBuilder<T>
  like<K extends StringKeyOf<T>>(
    column: K,
    pattern: string,
  ): EncryptedQueryBuilder<T>
  ilike<K extends StringKeyOf<T>>(
    column: K,
    pattern: string,
  ): EncryptedQueryBuilder<T>
  is<K extends StringKeyOf<T>>(
    column: K,
    value: null | boolean,
  ): EncryptedQueryBuilder<T>
  in<K extends StringKeyOf<T>>(
    column: K,
    values: T[K][],
  ): EncryptedQueryBuilder<T>
  filter<K extends StringKeyOf<T>>(
    column: K,
    operator: string,
    value: T[K],
  ): EncryptedQueryBuilder<T>
  not<K extends StringKeyOf<T>>(
    column: K,
    operator: string,
    value: T[K],
  ): EncryptedQueryBuilder<T>
  or(
    filters: string,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T>
  or(
    conditions: PendingOrCondition[],
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T>
  match(query: Partial<T>): EncryptedQueryBuilder<T>
  order<K extends StringKeyOf<T>>(
    column: K,
    options?: {
      ascending?: boolean
      nullsFirst?: boolean
      referencedTable?: string
      foreignTable?: string
    },
  ): EncryptedQueryBuilder<T>
  limit(
    count: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T>
  range(
    from: number,
    to: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): EncryptedQueryBuilder<T>
  single(): EncryptedQueryBuilder<T>
  maybeSingle(): EncryptedQueryBuilder<T>
  csv(): EncryptedQueryBuilder<T>
  abortSignal(signal: AbortSignal): EncryptedQueryBuilder<T>
  throwOnError(): EncryptedQueryBuilder<T>
  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilder<U>
  withLockContext(lockContext: LockContext): EncryptedQueryBuilder<T>
  audit(config: AuditConfig): EncryptedQueryBuilder<T>
}
