import type { AuditConfig } from '@cipherstash/stack/adapter-kit'
import type { EncryptionClient } from '@cipherstash/stack/encryption'
import type {
  AnyV3Table,
  EqlTypeForColumn,
  InferPlaintext,
  QueryTypesForColumn,
} from '@cipherstash/stack/eql/v3'
import type { EncryptionError } from '@cipherstash/stack/errors'
import type { LockContext, LockContextInput } from '@cipherstash/stack/identity'
import type {
  EncryptedTable,
  EncryptedTableColumn,
} from '@cipherstash/stack/schema'
import type { ClientConfig } from '@cipherstash/stack/types'
import type { V3Schemas } from './schema-builder'

// ---------------------------------------------------------------------------
// Config & instance
// ---------------------------------------------------------------------------

export type { V3Schemas }

/**
 * Options for {@link import('./index').encryptedSupabase}.
 *
 * @typeParam S - declared v3 tables. When present, `from()` is constrained to
 *   the declared table names and returns typed builders, and the tables are
 *   verified against the database at construction.
 */
export type EncryptedSupabaseOptions<
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
   * options. See the `contains` note on `EncryptedQueryBuilderImpl`.
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
export type NonQueryableKeys<Table extends AnyV3Table> = {
  [K in Extract<keyof V3ColumnsOfTable<Table>, string>]: [
    QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>,
  ] extends [never]
    ? K
    : never
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * The capability names a SCALAR predicate (`eq`/`neq`/`gt`/`gte`/`lt`/`lte`/
 * `in`) can exercise. `searchableJson` is deliberately absent: an encrypted
 * JSON document has no scalar terms, so a scalar predicate against it can only
 * ever fail at runtime.
 */
type ScalarQueryTypeName = 'equality' | 'orderAndRange' | 'freeTextSearch'

/**
 * JS property names of a v3 table's columns that support NO scalar predicate:
 * storage-only columns (no capability at all) AND `types.Json` columns (whose
 * only capability is `searchableJson` — containment/selector querying, reached
 * via `contains()`/`selectorEq()`/`selectorNe()` or the dedicated
 * `filter(col, 'cs', …)` / `not(col, 'contains', …)` overloads, never via a
 * scalar predicate).
 */
type NonScalarQueryableV3Keys<Table extends AnyV3Table> = {
  [K in Extract<keyof V3ColumnsOfTable<Table>, string>]: [
    Extract<
      QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>,
      ScalarQueryTypeName
    >,
  ] extends [never]
    ? K
    : never
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * Row keys a v3 builder accepts in SCALAR filter methods: every row key except
 * the table's encrypted columns with no scalar capability (storage-only
 * columns, and `types.Json` documents — see {@link NonScalarQueryableV3Keys};
 * before #650's `searchableJson` arm the two sets coincided). Plaintext
 * (non-schema) columns pass through untouched.
 */
export type FilterableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<Extract<keyof Row, string>, NonScalarQueryableV3Keys<Table>>

/**
 * JS property names of a v3 table's columns that carry NO `freeTextSearch`
 * capability — i.e. every domain but `public.eql_v3_text_match` and
 * `public.eql_v3_text_search`. Excluded from `contains()`'s keys, so a token-containment
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
export type FreeTextSearchableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<Extract<keyof Row, string>, NonFreeTextSearchV3Keys<Table>>

/**
 * Row keys `matches()` accepts: ONLY the table's ENCRYPTED columns that carry a
 * `freeTextSearch` capability (`public.eql_v3_text_match` / `text_search`).
 *
 * Unlike {@link FreeTextSearchableKeys} (which additionally lets plaintext keys
 * through, because the old `contains` also served native containment), this
 * excludes plaintext columns entirely — `matches()` is encrypted free-text only,
 * so calling it on a plaintext column is a compile error, not a runtime throw.
 * Derived from the encrypted-column keys minus the non-free-text ones.
 */
export type EncryptedFreeTextKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<
  Extract<keyof V3ColumnsOfTable<Table>, string>,
  NonFreeTextSearchV3Keys<Table>
> &
  Extract<keyof Row, string>

/**
 * JS property names of a v3 table's columns that carry NO `searchableJson`
 * capability — i.e. every domain but `public.eql_v3_json_search`. Mirror of
 * {@link NonFreeTextSearchV3Keys} for the encrypted-JSON capability.
 */
type NonSearchableJsonV3Keys<Table extends AnyV3Table> = {
  [K in Extract<
    keyof V3ColumnsOfTable<Table>,
    string
  >]: 'searchableJson' extends QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>
    ? never
    : K
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * Row keys the encrypted-JSON query methods accept (`contains()` on an
 * encrypted column, `selectorEq()`, `selectorNe()`): ONLY the table's ENCRYPTED
 * columns whose domain is `public.eql_v3_json_search` (`types.Json`). Plaintext
 * columns are excluded — on those, `contains()` is PostgREST-native containment
 * and the selector methods do not apply. Mirror of
 * {@link EncryptedFreeTextKeys} for the `searchableJson` capability.
 */
export type SearchableJsonKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<
  Extract<keyof V3ColumnsOfTable<Table>, string>,
  NonSearchableJsonV3Keys<Table>
> &
  Extract<keyof Row, string>

/**
 * The operand `contains()` accepts on an ENCRYPTED `types.Json` column: a
 * sub-document (object or array). The whole operand is storage-encrypted
 * against the column and compared via encrypted ste_vec containment — never a
 * raw PostgREST string form, which cannot be encrypted.
 */
export type EncryptedJsonContainsValue =
  | Record<string, unknown>
  | readonly unknown[]

/**
 * The scalar leaf value the selector methods compare at a JSONPath: exactly the
 * JSON scalar kinds a stored {@link import('@cipherstash/stack/eql/v3').JsonValue}
 * can carry. `Date` and `bigint` are deliberately absent — a `JsonDocument`
 * cannot contain them, so such a needle could never match a stored leaf
 * (serialize to the stored form first, e.g. `date.toISOString()`). Objects and
 * arrays are rejected too (that shape is `contains()`).
 */
export type SelectorLeafValue = string | number | boolean

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
 * The `contains()` operand for a PLAINTEXT column, derived from the column's own
 * declared shape.
 *
 * `@>` is defined on arrays and on jsonb, never on a scalar: `contains('note',
 * ['vip'])` against a plaintext `text` column emits `note.cs.{vip}` and Postgres
 * answers 42883 (operator does not exist). A scalar therefore maps to `never`,
 * which costs no legitimate call. `string` stays available on the container
 * columns for the raw-literal form (`contains('tags', '{vip}')`).
 */
type PlaintextContainsValue<V> = V extends readonly unknown[]
  ? V | string
  : V extends Record<string, unknown>
    ? V | string
    : never

/**
 * JS property names of a v3 table's columns that `order()` cannot sort by. Two
 * cases:
 *
 * 1. Columns with NO `orderAndRange` capability — storage-only, equality-only
 *    and match-only domains hold no ordering term.
 * 2. ORE-backed (`*_ord_ore`) columns. They ARE `orderAndRange`-capable, but the
 *    builder sorts encrypted columns through a jsonb path (`col->op`), and the
 *    OPE term that path selects does not exist on an ORE domain — its `ob` term
 *    needs the superuser-only ORE opclass no jsonb path can reach. So they are
 *    excluded here to match the runtime rejection in `validateTransforms`,
 *    rather than type-checking clean and throwing at execute time.
 */
export type NonOrderableKeys<Table extends AnyV3Table> = {
  [K in Extract<
    keyof V3ColumnsOfTable<Table>,
    string
  >]: 'orderAndRange' extends QueryTypesForColumn<V3ColumnsOfTable<Table>[K]>
    ? EqlTypeForColumn<V3ColumnsOfTable<Table>[K]> extends `${string}_ord_ore`
      ? K
      : never
    : K
}[Extract<keyof V3ColumnsOfTable<Table>, string>]

/**
 * Row keys a v3 builder accepts in `order()`: every plaintext row key, plus the
 * encrypted columns that carry an ordering term.
 *
 * A bare `ORDER BY col` on an EQL v3 domain IS wrong — the bundle declares no
 * btree opclass on any domain, so the sort resolves through jsonb's default
 * `jsonb_cmp` and compares the random ciphertext first. But the builder does not
 * emit a bare `ORDER BY`: for an encrypted ordering column it emits the jsonb
 * path `col->op`, which selects the OPE term, and OPE is order-preserving. See
 * `EncryptedQueryBuilderImpl.orderColumnName`.
 *
 * ORE-backed (`*_ord_ore`) columns are excluded at compile time by
 * {@link NonOrderableKeys} — the builder sorts through a jsonb path that
 * cannot reach their superuser-only ORE opclass, so `.order()` on one is a type
 * error, matching the runtime rejection in `validateTransforms` (defense in
 * depth for the untyped `.order(someString)` path).
 */
export type OrderableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<Extract<keyof Row, string>, NonOrderableKeys<Table>>

/**
 * Row keys that are NOT encrypted v3 columns. Used where a method's operand is a
 * SQL value rather than a ciphertext envelope — `is(col, true)` in particular,
 * since an encrypted column holds jsonb and can never be `IS TRUE`.
 */
export type PlaintextKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = Exclude<
  Extract<keyof Row, string>,
  Extract<keyof V3ColumnsOfTable<Table>, string>
>

/**
 * The v3 builder type: the shared {@link EncryptedQueryBuilderCore} surface with
 * filter methods narrowed to {@link FilterableKeys} and `order()` to
 * {@link OrderableKeys}.
 *
 * `like`/`ilike` are absent by construction. EQL v3 free-text search is fuzzy
 * bloom-filter token matching (`@>`), not SQL wildcard matching — `%` is
 * tokenized like any other character, so a `like` pattern is a category error.
 * The v3 dialect of Drizzle omits them for the same reason. Use `matches`.
 */
export interface EncryptedQueryBuilder<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> extends EncryptedQueryBuilderCore<
    Row,
    FilterableKeys<Table, Row> & StringKeyOf<Row>,
    EncryptedQueryBuilder<Table, Row>,
    OrderableKeys<Table, Row> & StringKeyOf<Row>,
    // `is(col, true)` is legal only on a PLAINTEXT column: an encrypted column
    // holds a jsonb envelope, never a SQL boolean. The two axes were threaded
    // separately "so they can diverge", and now they have — `order()` admits
    // encrypted ordering columns (sorted by their `op` term), `is(col, true)`
    // still admits none.
    PlaintextKeys<Table, Row> & StringKeyOf<Row>
  > {
  /** Encrypted free-text token match on legacy EQL versions. EQL 3.0.2+
   * requires a query-domain cast PostgREST cannot express, so this fails fast. */
  matches<K extends EncryptedFreeTextKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    value: string,
  ): EncryptedQueryBuilder<Table, Row>
  /** Native (exact) jsonb/array containment (`@>`). Plaintext columns only — an
   * encrypted column is a compile error (use {@link matches}). A scalar plaintext
   * column resolves its operand to `never` (`@>` is array/jsonb only). */
  contains<K extends PlaintextKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    value: PlaintextContainsValue<Row[K]>,
  ): EncryptedQueryBuilder<Table, Row>
  /** Encrypted JSON containment on legacy EQL versions. EQL 3.0.2+ requires an
   * `eql_v3.query_json` cast PostgREST cannot express, so this fails fast before
   * encrypting an operand into the request URL. */
  contains<K extends SearchableJsonKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    value: EncryptedJsonContainsValue,
  ): EncryptedQueryBuilder<Table, Row>
  /** Encrypted JSONPath equality on legacy EQL versions. EQL 3.0.2+ fails fast
   * because PostgREST cannot express the required query-domain cast. */
  selectorEq<K extends SearchableJsonKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    path: string,
    value: SelectorLeafValue,
  ): EncryptedQueryBuilder<Table, Row>
  /** Encrypted JSONPath inequality on legacy EQL versions. EQL 3.0.2+ fails
   * fast because PostgREST cannot express the required query-domain cast. */
  selectorNe<K extends SearchableJsonKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    path: string,
    value: SelectorLeafValue,
  ): EncryptedQueryBuilder<Table, Row>
  /** Raw legacy containment spelling. EQL 3.0.2+ rejects this before sending. */
  filter<K extends SearchableJsonKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    operator: 'cs',
    value: EncryptedJsonContainsValue,
  ): EncryptedQueryBuilder<Table, Row>
  filter<K extends FilterableKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    operator: string,
    value: Row[K],
  ): EncryptedQueryBuilder<Table, Row>
  /** Negated legacy containment spelling. EQL 3.0.2+ rejects this before
   * sending. */
  not<K extends SearchableJsonKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    operator: 'contains',
    value: EncryptedJsonContainsValue,
  ): EncryptedQueryBuilder<Table, Row>
  not<K extends FilterableKeys<Table, Row> & StringKeyOf<Row>>(
    column: K,
    operator: string,
    value: Row[K],
  ): EncryptedQueryBuilder<Table, Row>
}

/**
 * The builder for a table with no declared schema. Without capability
 * information `contains` cannot be narrowed to match-indexed columns — the
 * runtime guard in the term-encryption path is the only protection — and
 * `order()`/`is(col, true)` cannot be narrowed either, so this surface takes
 * {@link EncryptedQueryBuilderCore}'s `OK`/`BK` defaults. `like`/`ilike` are
 * absent here as on the typed surface.
 *
 * For the same reason nothing here can tell an encrypted match column from a
 * plaintext jsonb one, so `matches`/`contains` accept the full native operand
 * union (which subsumes the encrypted column's `string`); the runtime resolves
 * the column and picks the encoding (and rejects the wrong-column-kind pairing).
 */
export interface EncryptedQueryBuilderUntyped<
  Row extends Record<string, unknown>,
> extends EncryptedQueryBuilderCore<
    Row,
    StringKeyOf<Row>,
    EncryptedQueryBuilderUntyped<Row>
  > {
  /** Fuzzy free-text token match on an encrypted match/search column. The
   * operand is always the string term to tokenize (never an array/object), even
   * on the untyped surface where the column kind is unknown. */
  matches<K extends StringKeyOf<Row>>(
    column: K,
    value: string,
  ): EncryptedQueryBuilderUntyped<Row>
  /** Native jsonb/array containment on plaintext columns. Encrypted JSON
   * containment fails fast on EQL 3.0.2+. */
  contains<K extends StringKeyOf<Row>>(
    column: K,
    value: NativeContainsValue,
  ): EncryptedQueryBuilderUntyped<Row>
  /** Legacy encrypted JSONPath equality; fails fast on EQL 3.0.2+. */
  selectorEq<K extends StringKeyOf<Row>>(
    column: K,
    path: string,
    value: SelectorLeafValue,
  ): EncryptedQueryBuilderUntyped<Row>
  /** Legacy encrypted JSONPath inequality; fails fast on EQL 3.0.2+. */
  selectorNe<K extends StringKeyOf<Row>>(
    column: K,
    path: string,
    value: SelectorLeafValue,
  ): EncryptedQueryBuilderUntyped<Row>
}

/** Untyped instance (no `schemas`): rows default to `Record<string, unknown>`
 * and `from` accepts any table name. */
export interface EncryptedSupabaseInstance {
  from<Row extends Record<string, unknown> = Record<string, unknown>>(
    tableName: string,
  ): EncryptedQueryBuilderUntyped<Row>
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
export interface TypedEncryptedSupabaseInstance<S extends V3Schemas> {
  from<K extends keyof S & string>(
    table: K,
  ): EncryptedQueryBuilder<S[K], InferPlaintext<S[K]>>
  from<Row extends Record<string, unknown> = Record<string, unknown>>(
    table: string,
  ): EncryptedQueryBuilderUntyped<Row>
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/**
 * The builder returned by `single()`/`maybeSingle()`: awaits to a SINGLE row
 * (`data: T | null`) instead of an array.
 *
 * Only the two post-hoc modifiers supabase-js also allows after `.single()` are
 * carried over. Filters and transforms are deliberately absent — applying one
 * after `single()` would change the query the single-row promise was made
 * about.
 */
export interface EncryptedSingleQueryBuilder<T>
  extends PromiseLike<EncryptedSupabaseResponse<T>> {
  abortSignal(signal: AbortSignal): EncryptedSingleQueryBuilder<T>
  throwOnError(): EncryptedSingleQueryBuilder<T>
}

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
  /** Native jsonb/array containment (PostgREST `cs` → `@>`). Plaintext columns
   * on the v3 surface; also the encrypted-JSON path where applicable. */
  | 'contains'
  /** Encrypted free-text token match (bloom `@>`). v3 encrypted match/search
   * columns only. Same `cs` wire operator as `contains`, different semantics. */
  | 'matches'
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
// `toDbSpace()` (see ./query-dbspace) maps the property-space IR above into
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

/** The whole recorded query, in PROPERTY space — the builder's chained state as
 * handed to `toDbSpace()`. The mirror of {@link DbQuerySpace} on the untranslated
 * side of that boundary. */
export type RecordedOps = {
  filters: PendingFilter[]
  matchFilters: PendingMatchFilter[]
  notFilters: PendingNotFilter[]
  rawFilters: PendingRawFilter[]
  orFilters: PendingOrFilter[]
  transforms: TransformOp[]
  mutation: MutationOp | null
}

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

export type { AuditConfig } from '@cipherstash/stack/adapter-kit'
export type { EncryptionClient } from '@cipherstash/stack/encryption'
export type {
  LockContext,
  LockContextInput,
} from '@cipherstash/stack/identity'
export type {
  EncryptedColumn,
  EncryptedTable,
  EncryptedTableColumn,
} from '@cipherstash/stack/schema'

// ---------------------------------------------------------------------------
// Forward declaration for query builder (avoids circular)
// ---------------------------------------------------------------------------

/** Helper to extract string keys from T */
type StringKeyOf<T> = Extract<keyof T, string>

/**
 * Every builder method shared by the TYPED ({@link EncryptedQueryBuilder}) and
 * UNTYPED ({@link EncryptedQueryBuilderUntyped}) surfaces. Both are EQL v3 —
 * they differ only in how much they can narrow, not in dialect.
 *
 * `Self` is the concrete builder each method returns, so a surface that omits a
 * method does not have it laundered back in by a chained call whose return type
 * widened to the base interface.
 *
 * Free-text search lives on the sub-interfaces rather than here, because its
 * key set differs between the two: `matches()` narrows to the encrypted
 * match/search columns on the typed surface, and to every row key on the
 * untyped one. Neither surface carries `like`/`ilike` — EQL v3 free-text is
 * fuzzy bloom-token matching, not SQL pattern matching, so the builder rewrites
 * a `like` on an encrypted column to `matches` at record time (see
 * `query-builder.ts`). They survive in this file only as the internal
 * {@link FilterOp} union and on the raw {@link SupabaseQueryBuilder} seam, both
 * of which still serve plaintext columns.
 */
export interface EncryptedQueryBuilderCore<
  T extends Record<string, unknown>,
  FK extends StringKeyOf<T>,
  Self,
  /** Keys `order()` accepts. The typed surface narrows it to the orderable
   * columns (see {@link OrderableKeys}); it defaults to `FK` for the untyped
   * surface, which has no capability information to narrow with. */
  OK extends StringKeyOf<T> = FK,
  /** Keys the BOOLEAN form of `is()` accepts. The typed surface narrows it to
   * plaintext columns; it defaults to `FK` for the untyped surface, as `OK`
   * does. Distinct from `OK` on purpose: "sortable" and "IS TRUE-able" are
   * different capability axes that happen to select the same keys today, and
   * narrowing `order()` later must not silently narrow `is()` with it. */
  BK extends StringKeyOf<T> = FK,
> extends PromiseLike<EncryptedSupabaseResponse<T[]>> {
  /** `columns` defaults to `'*'`, matching supabase-js. A `'*'` select expands
   * to the introspected column list; when none is available (a client that
   * could not introspect) both `select()` and `select('*')` throw, because an
   * unexpanded `*` cannot cast the encrypted columns with `::jsonb`. */
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
   * The boolean form narrows to `BK`: `IS TRUE` against a jsonb ciphertext
   * column compares an envelope to a plaintext boolean, which is a type error in
   * the database, not a filter. `FK` is the wrong gate for it — that set
   * excludes only the STORAGE-ONLY columns, so a queryable encrypted column
   * (`types.TextSearch`, `types.TextEq`, any `*_ord`) is in `FK` and would still
   * compile `is(col, true)`. Every encrypted column stores an envelope,
   * capability or not, so `BK` excludes them all.
   */
  is<K extends BK>(column: K, value: null | boolean): Self
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
  // `OK`, not `FK`: an encrypted column is orderable only when its domain
  // carries an OPE term (PostgREST reaches it as `col->op`); a bare `ORDER BY`
  // would sort the ciphertext envelope. `OK` defaults to `FK` on the untyped
  // surface, where the runtime `validateTransforms` guard is the only check.
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
  /**
   * Return ONE row rather than an array — so the awaited `data` is `T | null`,
   * not `T[]`. Returns {@link EncryptedSingleQueryBuilder} rather than `Self`
   * because that change of shape is the whole point of the call: typing it
   * `Self` would keep promising `T[]` while the runtime hands back one object,
   * forcing every caller through a cast (`data as unknown as Row`).
   *
   * Filters and transforms are not chainable afterwards, matching supabase-js —
   * `single()` is applied last.
   */
  single(): EncryptedSingleQueryBuilder<T>
  /** As {@link single}, but a zero-row result is `data: null` rather than an
   * error. Same `T | null` awaited shape — `single()` reports the missing row
   * through `error` instead. */
  maybeSingle(): EncryptedSingleQueryBuilder<T>
  csv(): Self
  abortSignal(signal: AbortSignal): Self
  throwOnError(): Self
  /** Escape hatch: re-types the rows and drops back to the untyped v3 builder
   * surface. */
  returns<U extends Record<string, unknown>>(): EncryptedQueryBuilderUntyped<U>
  /** Bind identity-aware encryption. Accepts either a plain
   * `{ identityClaim }` (the common form) or a `LockContext` instance. */
  withLockContext(lockContext: LockContextInput): Self
  audit(config: AuditConfig): Self
}

// ---------------------------------------------------------------------------
// Deprecated `*V3` aliases (Decision 5 — supabase keeps type-identical aliases).
// The v3 names are now the unsuffixed canonical exports; these aliases keep
// existing `*V3` imports compiling.
// ---------------------------------------------------------------------------

/** @deprecated Use {@link EncryptedSupabaseOptions}. */
export type EncryptedSupabaseV3Options<
  S extends V3Schemas | undefined = undefined,
> = EncryptedSupabaseOptions<S>

/** @deprecated Use {@link NonQueryableKeys}. */
export type NonQueryableV3Keys<Table extends AnyV3Table> =
  NonQueryableKeys<Table>

/** @deprecated Use {@link FilterableKeys}. */
export type V3FilterableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = FilterableKeys<Table, Row>

/** @deprecated Use {@link FreeTextSearchableKeys}. */
export type V3FreeTextSearchableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = FreeTextSearchableKeys<Table, Row>

/** @deprecated Use {@link EncryptedFreeTextKeys}. */
export type V3EncryptedFreeTextKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = EncryptedFreeTextKeys<Table, Row>

/** @deprecated Use {@link SearchableJsonKeys}. */
export type V3SearchableJsonKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = SearchableJsonKeys<Table, Row>

/** @deprecated Use {@link NonOrderableKeys}. */
export type NonOrderableV3Keys<Table extends AnyV3Table> =
  NonOrderableKeys<Table>

/** @deprecated Use {@link OrderableKeys}. */
export type V3OrderableKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = OrderableKeys<Table, Row>

/** @deprecated Use {@link PlaintextKeys}. */
export type V3PlaintextKeys<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = PlaintextKeys<Table, Row>

/** @deprecated Use {@link EncryptedQueryBuilder}. */
export type EncryptedQueryBuilderV3<
  Table extends AnyV3Table,
  Row extends Record<string, unknown>,
> = EncryptedQueryBuilder<Table, Row>

/** @deprecated Use {@link EncryptedQueryBuilderUntyped}. */
export type EncryptedQueryBuilderV3Untyped<
  Row extends Record<string, unknown>,
> = EncryptedQueryBuilderUntyped<Row>

/** @deprecated Use {@link EncryptedSupabaseInstance}. */
export type EncryptedSupabaseV3Instance = EncryptedSupabaseInstance

/** @deprecated Use {@link TypedEncryptedSupabaseInstance}. */
export type TypedEncryptedSupabaseV3Instance<S extends V3Schemas> =
  TypedEncryptedSupabaseInstance<S>
