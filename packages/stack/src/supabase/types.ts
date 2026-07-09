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
   * Declaring a `text_search` column does NOT change its match behaviour: a
   * declared and a synthesized `text_search` column build byte-identically, and
   * neither `types.TextSearch` nor `EncryptedTextSearchColumn` accepts match
   * options. `include_original: true` is therefore always in force, so a
   * substring `contains` matches nothing on either. See the `contains` note on
   * `EncryptedQueryBuilderV3Impl`.
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
 * JS property names of a v3 table's columns that carry NO `freeTextSearch`
 * capability — i.e. every domain but `public.text_match` and
 * `public.text_search`. Excluded from `contains()`'s keys, so a token-containment
 * query against a column with no bloom-filter index is a type error rather than
 * the runtime capability throw in the v3 term encryption path.
 */
type NonFreeTextSearchV3Keys<Table extends AnyV3Table> = {
  [K in Extract<
    keyof V3ColumnsOfTable<Table>,
    string
  >]: 'freeTextSearch' extends QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>
    ? never
    : K
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * Row keys a v3 builder accepts in `contains()`: every row key except the
 * table's encrypted columns that lack a match index. Plaintext columns pass
 * through, where `contains` is PostgREST's native jsonb/array containment.
 */
export type V3FreeTextSearchableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<Extract<keyof Row, string>, NonFreeTextSearchV3Keys<Table>>

/**
 * The operand `contains()` accepts on a PLAINTEXT column, mirroring
 * postgrest-js's own untyped `contains` overload: a jsonb literal, an array, or
 * the raw string form.
 *
 * Deliberately NOT `ReadonlyArray<Row[K]>` (postgrest-js's *typed* overload):
 * for `tags: string[]` that resolves to `string[][]` and rejects the very call
 * it exists to allow, `contains('tags', ['vip'])`.
 */
type NativeContainsValue = string | readonly unknown[] | Record<string, unknown>

/**
 * The `contains()` operand for column `K`.
 *
 * A DECLARED encrypted column reaching `contains` necessarily carries a
 * `freeTextSearch` capability — only `public.text_match` and
 * `public.text_search` do, and both `cast_as` to `string` — so its operand is
 * the string to tokenize into a bloom-filter query term.
 *
 * Any other key is a plaintext passthrough, where the runtime forwards the
 * operand untouched to `q.contains` and `contains` means PostgREST's native
 * jsonb/array containment. A blanket `value: string` made that half of
 * {@link V3FreeTextSearchableKeys} unreachable from TypeScript.
 *
 * `[K] extends [...]` rather than a bare conditional: a naked type parameter
 * distributes over unions, which would silently widen a union key to the union
 * of both operand types instead of demanding every member be a declared column.
 */
export type V3ContainsValue<Table extends AnyV3Table, K extends string> = [
  K,
] extends [Extract<keyof V3ColumnsOfTable<Table>, string>]
  ? string
  : NativeContainsValue

/**
 * Row keys a v3 builder accepts in `order()`: every row key that is NOT an
 * encrypted v3 column. `ORDER BY` on an EQL v3 domain sorts the raw ciphertext
 * envelope — the bundle declares no btree operator class on any domain, so the
 * sort resolves through jsonb's default `jsonb_cmp`. Correct ordering needs
 * `eql_v3.ord_term(col)`, which PostgREST cannot emit.
 */
export type V3OrderableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<
  Extract<keyof Row, string>,
  Extract<keyof V3ColumnsOfTable<Table>, string>
>

/**
 * The v3 builder type: the shared {@link EncryptedQueryBuilderCore} surface with
 * filter methods narrowed to {@link V3FilterableKeys} and `order()` to
 * {@link V3OrderableKeys}.
 *
 * `like`/`ilike` are absent by construction. EQL v3 free-text search is token
 * containment over a bloom filter (`@>`), not SQL wildcard matching — `%` is
 * tokenized like any other character, so a `like` pattern is a category error.
 * The v3 dialect of Drizzle omits them for the same reason. Use `contains`.
 */
export interface EncryptedQueryBuilderV3<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> extends EncryptedQueryBuilderCore<
    Row,
    V3FilterableKeys<Table, Row> & StringKeyOf<Row>,
    EncryptedQueryBuilderV3<Table, Row>,
    V3OrderableKeys<Table, Row> & StringKeyOf<Row>
  > {
  contains<K extends V3FreeTextSearchableKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    value: V3ContainsValue<Table, K>,
  ): EncryptedQueryBuilderV3<Table, Row>
}

/**
 * The v3 builder for a table with no declared schema. Without capability
 * information `contains` cannot be narrowed to match-indexed columns — the
 * runtime guard in the term-encryption path is the only protection — but the
 * DIALECT is still v3, so `like`/`ilike` are absent here too. Typing this as
 * {@link EncryptedQueryBuilder} would hand back the v2 surface.
 *
 * For the same reason nothing here can tell an encrypted match column from a
 * plaintext jsonb one, so `contains` accepts the full native operand union
 * (which subsumes the encrypted column's `string`); the runtime resolves the
 * column and picks the encoding.
 */
export interface EncryptedQueryBuilderV3Untyped<
  Row extends Record<string, unknown>,
> extends EncryptedQueryBuilderCore<
    Row,
    StringKeyOf<Row>,
    EncryptedQueryBuilderV3Untyped<Row>
  > {
  contains<K extends StringKeyOf<Row>>(
    column: K,
    value: NativeContainsValue,
  ): EncryptedQueryBuilderV3Untyped<Row>
}

/** Untyped instance (no `schemas`): rows default to `Record<string, unknown>`
 * and `from` accepts any table name. */
export interface EncryptedSupabaseV3Instance {
  from<Row extends Record<string, unknown> = Record<string, unknown>>(
    tableName: string,
  ): EncryptedQueryBuilderV3Untyped<Row>
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
  ): EncryptedQueryBuilderV3Untyped<Row>
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
  /** Token containment. v3-only on encrypted columns; on a plaintext column it
   * is PostgREST's native jsonb/array `cs`. */
  | 'contains'
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
  /** PostgREST's `column.not.<op>.<value>` negation. Kept off `op` so the
   * `in`-list split and the query-type mapping both key on the real operator. */
  negate?: boolean
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
// DB-space brands
// ---------------------------------------------------------------------------

declare const DbBrand: unique symbol

/**
 * A column name in DB-space — i.e. one PostgREST will recognise.
 *
 * A v3 table may declare a column whose JS property name differs from its DB
 * column name (`createdAt: types.TimestampOrd('created_at')`). Both are
 * `string`, so before these brands the compiler could not tell which of the two
 * reached PostgREST, and each new column-carrying method silently started out
 * broken — that is how `order()` shipped sending `createdAt` to a database that
 * only has `created_at`.
 *
 * Branding the {@link SupabaseQueryBuilder} seam means a property name will not
 * type-check where a DB name is required. The only way to obtain a `DbName` is
 * to call `filterColumnName()`, so forgetting to translate is now a compile
 * error rather than a wrong query. The brand is erased at runtime.
 */
export type DbName = string & { readonly [DbBrand]: 'column' }

/** A PostgREST select list, DB-space and `::jsonb`-cast. Minted by `addJsonbCasts`/`addJsonbCastsV3`. */
export type DbSelect = string & { readonly [DbBrand]: 'select' }

/** A PostgREST `or()` filter string in DB-space. Minted by `rebuildOrString`. */
export type DbFilterString = string & { readonly [DbBrand]: 'filter' }

/** A comma-separated `onConflict` column list in DB-space. Minted by `resolveMutationOptions`. */
export type DbConflictList = string & { readonly [DbBrand]: 'conflict' }

/** Mutation options, with the one column-carrying member in DB-space. */
export type DbMutationOptions = Record<string, unknown> & {
  onConflict?: DbConflictList
}

// ---------------------------------------------------------------------------
// DB-space IR — the recorded query, with every column name translated.
//
// `toDbSpace()` (see ./query-builder) maps the property-space IR above into
// this one, exactly once, before any column name can reach PostgREST. The
// branded `column` fields make that translation a compile-time obligation:
// `applyFilters`/`buildAndExecuteQuery` consume only these types, so feeding
// them the untranslated `PendingFilter[]` does not type-check.
// ---------------------------------------------------------------------------

export type DbPendingFilter = Omit<PendingFilter, 'column'> & { column: DbName }
export type DbPendingNotFilter = Omit<PendingNotFilter, 'column'> & {
  column: DbName
}
export type DbPendingRawFilter = Omit<PendingRawFilter, 'column'> & {
  column: DbName
}
export type DbPendingOrCondition = Omit<PendingOrCondition, 'column'> & {
  column: DbName
}

/** Entries rather than a Record: a brand cannot ride on an object key, so this
 * is the one translation the compiler cannot enforce. Order is preserved. */
export type DbPendingMatchFilter = {
  entries: Array<{ column: DbName; value: unknown }>
}

/** Retains the caller's ORIGINAL text for the verbatim fallback (which must be
 * forwarded byte-for-byte — `parseOrString`/`rebuildOrString` do not round-trip
 * nested `and()` or quoted values) alongside the parsed DB-space conditions
 * used by the encrypt-and-rebuild path. Parsing happens once, here. */
export type DbPendingOrFilter =
  | { kind: 'structured'; conditions: DbPendingOrCondition[] }
  | {
      kind: 'string'
      original: string
      conditions: DbPendingOrCondition[]
      referencedTable?: string
    }

type OrderOp = Extract<TransformOp, { kind: 'order' }>
export type DbTransformOp =
  | Exclude<TransformOp, OrderOp>
  | (Omit<OrderOp, 'column'> & { column: DbName })

type InsertOp = Extract<MutationOp, { kind: 'insert' }>
type UpsertOp = Extract<MutationOp, { kind: 'upsert' }>
export type DbMutationOp =
  | (Omit<InsertOp, 'options'> & { options?: DbMutationOptions })
  | (Omit<UpsertOp, 'options'> & { options?: DbMutationOptions })
  | Extract<MutationOp, { kind: 'update' }>
  | Extract<MutationOp, { kind: 'delete' }>

/** The whole recorded query, in DB-space. */
export type DbQuerySpace = {
  filters: DbPendingFilter[]
  matchFilters: DbPendingMatchFilter[]
  notFilters: DbPendingNotFilter[]
  rawFilters: DbPendingRawFilter[]
  orFilters: DbPendingOrFilter[]
  transforms: DbTransformOp[]
  mutation: DbMutationOp | null
}

// ---------------------------------------------------------------------------
// Minimal Supabase client shape (to avoid hard dependency)
// ---------------------------------------------------------------------------

export interface SupabaseQueryBuilder {
  select(
    columns?: DbSelect,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): SupabaseQueryBuilder
  insert(values: unknown, options?: DbMutationOptions): SupabaseQueryBuilder
  update(values: unknown, options?: DbMutationOptions): SupabaseQueryBuilder
  upsert(values: unknown, options?: DbMutationOptions): SupabaseQueryBuilder
  delete(options?: Record<string, unknown>): SupabaseQueryBuilder
  eq(column: DbName, value: unknown): SupabaseQueryBuilder
  neq(column: DbName, value: unknown): SupabaseQueryBuilder
  gt(column: DbName, value: unknown): SupabaseQueryBuilder
  gte(column: DbName, value: unknown): SupabaseQueryBuilder
  lt(column: DbName, value: unknown): SupabaseQueryBuilder
  lte(column: DbName, value: unknown): SupabaseQueryBuilder
  like(column: DbName, value: unknown): SupabaseQueryBuilder
  ilike(column: DbName, value: unknown): SupabaseQueryBuilder
  contains(column: DbName, value: unknown): SupabaseQueryBuilder
  is(column: DbName, value: unknown): SupabaseQueryBuilder
  in(column: DbName, values: unknown[]): SupabaseQueryBuilder
  filter(column: DbName, operator: string, value: unknown): SupabaseQueryBuilder
  not(column: DbName, operator: string, value: unknown): SupabaseQueryBuilder
  or(
    filters: DbFilterString,
    options?: { referencedTable?: string; foreignTable?: string },
  ): SupabaseQueryBuilder
  match(query: Record<string, unknown>): SupabaseQueryBuilder
  order(column: DbName, options?: Record<string, unknown>): SupabaseQueryBuilder
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

/**
 * Every builder method shared by the v2 and v3 dialects. `Self` is the concrete
 * builder each method returns, so a dialect that omits a method (v3 omits
 * `like`/`ilike`) does not have it laundered back in by a chained call whose
 * return type widened to the base interface.
 *
 * Free-text search is the ONLY axis on which the two dialects differ: v2
 * matches with SQL wildcards (`like`/`ilike` → `~~`), v3 with token containment
 * (`contains` → `@>`). Each adds its own method below.
 */
export interface EncryptedQueryBuilderCore<
  T extends Record<string, unknown>,
  FK extends StringKeyOf<T>,
  Self,
  /** Keys `order()` accepts. Defaults to `FK`, so the v2 surface is unchanged;
   * v3 narrows it to plaintext columns (see {@link V3OrderableKeys}). */
  OK extends StringKeyOf<T> = FK,
> extends PromiseLike<EncryptedSupabaseResponse<T[]>> {
  /** `columns` defaults to `'*'`, matching supabase-js. A `'*'` select expands
   * to the introspected column list when one is available (v3), and otherwise
   * throws — v2 has no column list to cast, so `select()` and `select('*')`
   * both throw there. */
  select(
    columns?: string,
    options?: { head?: boolean; count?: 'exact' | 'planned' | 'estimated' },
  ): Self
  insert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      defaultToNull?: boolean
      onConflict?: string
    },
  ): Self
  update(
    data: Partial<T>,
    options?: { count?: 'exact' | 'planned' | 'estimated' },
  ): Self
  upsert(
    data: Partial<T> | Partial<T>[],
    options?: {
      count?: 'exact' | 'planned' | 'estimated'
      onConflict?: string
      ignoreDuplicates?: boolean
      defaultToNull?: boolean
    },
  ): Self
  delete(options?: { count?: 'exact' | 'planned' | 'estimated' }): Self
  eq<K extends FK>(column: K, value: T[K]): Self
  neq<K extends FK>(column: K, value: T[K]): Self
  gt<K extends FK>(column: K, value: T[K]): Self
  gte<K extends FK>(column: K, value: T[K]): Self
  lt<K extends FK>(column: K, value: T[K]): Self
  lte<K extends FK>(column: K, value: T[K]): Self
  /**
   * `IS NULL` / `IS TRUE` / `IS FALSE`.
   *
   * The `null` form is widened to EVERY row key, not just the filterable ones.
   * `is` is the one predicate never encrypted — `isEncryptableTerm` rejects it
   * outright, so no term is collected and no capability guard runs — and a NULL
   * plaintext is stored as a SQL NULL rather than a ciphertext. On a v3
   * storage-only column (`types.Boolean`, `types.Integer`, …) `IS NULL` is
   * therefore not merely legal but the ONLY predicate available, so narrowing it
   * to `FK` would deny the sole query those columns support.
   *
   * The boolean form stays on `FK`: `IS TRUE` against a jsonb ciphertext column
   * compares an envelope to a plaintext boolean, which is a type error in the
   * database, not a filter.
   */
  is<K extends FK>(column: K, value: null | boolean): Self
  is<K extends StringKeyOf<T>>(column: K, value: null): Self
  in<K extends FK>(column: K, values: T[K][]): Self
  filter<K extends FK>(column: K, operator: string, value: T[K]): Self
  not<K extends FK>(column: K, operator: string, value: T[K]): Self
  or(
    filters: string,
    options?: { referencedTable?: string; foreignTable?: string },
  ): Self
  or(
    conditions: PendingOrCondition[],
    options?: { referencedTable?: string; foreignTable?: string },
  ): Self
  match(query: Partial<T>): Self
  // `OK`, not `FK`: v3 cannot order by ANY encrypted column, because PostgREST
  // cannot emit `ORDER BY eql_v3.ord_term(col)` and a bare `ORDER BY` sorts the
  // ciphertext envelope. `OK` defaults to `FK`, so the v2 surface is unchanged.
  order<K extends OK>(
    column: K,
    options?: {
      ascending?: boolean
      nullsFirst?: boolean
      referencedTable?: string
      foreignTable?: string
    },
  ): Self
  limit(
    count: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): Self
  range(
    from: number,
    to: number,
    options?: { referencedTable?: string; foreignTable?: string },
  ): Self
  single(): Self
  maybeSingle(): Self
  csv(): Self
  abortSignal(signal: AbortSignal): Self
  throwOnError(): Self
  /** Escape hatch: re-types the rows and drops back to the v2 builder surface. */
  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilder<U>
  withLockContext(lockContext: LockContext): Self
  audit(config: AuditConfig): Self
}

/** The v2 builder: free-text search via SQL wildcard matching. */
export interface EncryptedQueryBuilder<
  T extends Record<string, unknown> = Record<string, unknown>,
  FK extends StringKeyOf<T> = StringKeyOf<T>,
> extends EncryptedQueryBuilderCore<T, FK, EncryptedQueryBuilder<T, FK>> {
  like<K extends FK>(column: K, pattern: string): EncryptedQueryBuilder<T, FK>
  ilike<K extends FK>(column: K, pattern: string): EncryptedQueryBuilder<T, FK>
}
