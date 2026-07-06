import type { ColumnSchema, MatchIndexOpts } from '@/schema'
import {
  type BuiltMatchIndexOpts,
  cloneMatchOpts,
  defaultMatchOpts,
  resolveMatchOpts,
} from '@/schema/match-defaults'

/**
 * The query capabilities a v3 concrete domain exposes. These are SDK-facing
 * semantic flags describing what kinds of query terms a column can produce —
 * NOT the raw EQL index keys. They are metadata only and never emitted by
 * `build()`.
 *
 * - `equality`: exact-match lookups (EQL `hm`, or comparison via `ob`).
 * - `orderAndRange`: comparison / range lookups (EQL `ob`).
 * - `freeTextSearch`: tokenised substring match (EQL `bf`).
 */
export type QueryCapabilities = Readonly<{
  equality: boolean
  orderAndRange: boolean
  freeTextSearch: boolean
}>

/**
 * The `cast_as` kinds whose decrypted plaintext reconstructs to a JS `Date`.
 *
 * SINGLE SOURCE OF TRUTH for the date-like set. Both the type-level
 * {@link PlaintextFromKind} and the runtime `rowReconstructor` (encryption/v3.ts)
 * derive their "reconstructs to `Date`" decision from this array, so the next
 * `Date`-backed cast is added in exactly one place — never hand-synced across a
 * type and a runtime guard that could silently drift.
 *
 * (`timestamp` reconstructs to `Date` just like `date`, but its `cast_as` tells
 * the FFI not to truncate the time-of-day.)
 */
export const DATE_LIKE_CASTS = ['date', 'timestamp'] as const
/** A `cast_as` kind that reconstructs to `Date` — see {@link DATE_LIKE_CASTS}. */
export type DateLikeCast = (typeof DATE_LIKE_CASTS)[number]

/** The plaintext (TypeScript) kind a v3 domain decrypts to. A subset of the
 * SDK `CastAs` enum, restricted to the scalar kinds v3 domains actually use. */
type PlaintextKind = 'string' | 'number' | 'boolean' | DateLikeCast

/**
 * The full, literal definition of a v3 domain. This is the LOAD-BEARING type:
 * the base column class carries a private field of this type so that every
 * concrete (otherwise-empty) subclass is discriminated by its literal
 * `eqlType`/`castAs`/`capabilities` — TypeScript empty subclasses are NOT
 * nominal, so without this a storage-only `bool` column would be assignable to
 * a storage-only `date` column and plaintext inference would collapse.
 */
type V3DomainDefinition = Readonly<{
  eqlType: `eql_v3.${string}`
  castAs: PlaintextKind
  capabilities: QueryCapabilities
}>

/** Type-level mirror of {@link isQueryableCapabilities}: `false` for a
 * storage-only domain (all capability flags `false`), `true` otherwise. */
type QueryableFlag<D extends V3DomainDefinition> = D['capabilities'] extends {
  equality: false
  orderAndRange: false
  freeTextSearch: false
}
  ? false
  : true

const STORAGE_ONLY = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: false,
} as const

const EQUALITY_ONLY = {
  equality: true,
  orderAndRange: false,
  freeTextSearch: false,
} as const

const ORDER_AND_RANGE = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: false,
} as const

const MATCH_ONLY = {
  equality: false,
  orderAndRange: false,
  freeTextSearch: true,
} as const

const TEXT_SEARCH = {
  equality: true,
  orderAndRange: true,
  freeTextSearch: true,
} as const

/**
 * The concrete EQL v3 domain name for a full-capability text column.
 * Recorded as metadata for future DDL / query-dialect increments; it is
 * intentionally absent from the emitted encrypt config.
 */
export const TEXT_SEARCH_EQL_TYPE = 'eql_v3.text_search'

// Per-domain literal definitions. Each concrete column subclass is parameterised
// by `typeof <CONST>`; the literal `eqlType`/`castAs`/`capabilities` on each is
// what makes the otherwise-empty subclasses nominally distinct (see
// V3DomainDefinition). Order mirrors eql-bindings `CATALOG` order.
//
// Exported for the `types` namespace factory (see ./types); they are internal
// building blocks and are intentionally NOT re-exported from the public barrel.
export const INT4 = {
  eqlType: 'eql_v3.int4',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const INT4_EQ = {
  eqlType: 'eql_v3.int4_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const INT4_ORD_ORE = {
  eqlType: 'eql_v3.int4_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const INT4_ORD = {
  eqlType: 'eql_v3.int4_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const INT2 = {
  eqlType: 'eql_v3.int2',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const INT2_EQ = {
  eqlType: 'eql_v3.int2_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const INT2_ORD_ORE = {
  eqlType: 'eql_v3.int2_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const INT2_ORD = {
  eqlType: 'eql_v3.int2_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

// NOTE: int8 (bigint) domains are intentionally NOT defined yet. The native
// protect-ffi build cannot round-trip a 64-bit int losslessly: a JS `bigint`
// fails JSON serialization, and a `string` is rejected for a `big_int` column
// ("Cannot convert String to BigInt"), while `number` loses precision above
// 2^53. Re-add INT8/INT8_EQ/INT8_ORD_ORE/INT8_ORD and their builders once the
// FFI accepts a lossless bigint on input and returns it on decrypt.

export const DATE = {
  eqlType: 'eql_v3.date',
  castAs: 'date',
  capabilities: STORAGE_ONLY,
} as const
export const DATE_EQ = {
  eqlType: 'eql_v3.date_eq',
  castAs: 'date',
  capabilities: EQUALITY_ONLY,
} as const
export const DATE_ORD_ORE = {
  eqlType: 'eql_v3.date_ord_ore',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const
export const DATE_ORD = {
  eqlType: 'eql_v3.date_ord',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const

export const TIMESTAMP = {
  eqlType: 'eql_v3.timestamp',
  castAs: 'timestamp',
  capabilities: STORAGE_ONLY,
} as const
export const TIMESTAMP_EQ = {
  eqlType: 'eql_v3.timestamp_eq',
  castAs: 'timestamp',
  capabilities: EQUALITY_ONLY,
} as const
export const TIMESTAMP_ORD_ORE = {
  eqlType: 'eql_v3.timestamp_ord_ore',
  castAs: 'timestamp',
  capabilities: ORDER_AND_RANGE,
} as const
export const TIMESTAMP_ORD = {
  eqlType: 'eql_v3.timestamp_ord',
  castAs: 'timestamp',
  capabilities: ORDER_AND_RANGE,
} as const

export const NUMERIC = {
  eqlType: 'eql_v3.numeric',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const NUMERIC_EQ = {
  eqlType: 'eql_v3.numeric_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const NUMERIC_ORD_ORE = {
  eqlType: 'eql_v3.numeric_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const NUMERIC_ORD = {
  eqlType: 'eql_v3.numeric_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const TEXT = {
  eqlType: 'eql_v3.text',
  castAs: 'string',
  capabilities: STORAGE_ONLY,
} as const
export const TEXT_EQ = {
  eqlType: 'eql_v3.text_eq',
  castAs: 'string',
  capabilities: EQUALITY_ONLY,
} as const
export const TEXT_MATCH = {
  eqlType: 'eql_v3.text_match',
  castAs: 'string',
  capabilities: MATCH_ONLY,
} as const
export const TEXT_ORD_ORE = {
  eqlType: 'eql_v3.text_ord_ore',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const
export const TEXT_ORD = {
  eqlType: 'eql_v3.text_ord',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const

export const BOOL = {
  eqlType: 'eql_v3.bool',
  castAs: 'boolean',
  capabilities: STORAGE_ONLY,
} as const

export const FLOAT4 = {
  eqlType: 'eql_v3.float4',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const FLOAT4_EQ = {
  eqlType: 'eql_v3.float4_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const FLOAT4_ORD_ORE = {
  eqlType: 'eql_v3.float4_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const FLOAT4_ORD = {
  eqlType: 'eql_v3.float4_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const FLOAT8 = {
  eqlType: 'eql_v3.float8',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const FLOAT8_EQ = {
  eqlType: 'eql_v3.float8_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const FLOAT8_ORD_ORE = {
  eqlType: 'eql_v3.float8_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const FLOAT8_ORD = {
  eqlType: 'eql_v3.float8_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

/**
 * Translate a domain's semantic {@link QueryCapabilities} (plus its plaintext
 * `castAs`, which decides how equality is answered) into the concrete EQL index
 * block emitted by `build()`.
 *
 * - `unique` (the `hm` HMAC index) whenever equality is answered via HMAC:
 *   equality-only domains of ANY type, AND text order domains. Text equality is
 *   HMAC-based — the `eql_v3.text_ord` / `eql_v3.text_ord_ore` SQL domains
 *   REQUIRE `hm` in the stored ciphertext (their `eql_v3.eq_term` extracts it).
 * - `ore` for any order/range domain (the `ob` term). For numeric/date order
 *   domains `ob` also answers equality (via the SQL `=` operator), so those emit
 *   `ore` ONLY — no `hm`. Text order domains emit BOTH `unique` and `ore`.
 * - `match` (the `bf` bloom-filter index) for free-text search, deep-cloned from
 *   the per-call defaults so no nested object is ever shared across columns.
 */
function indexesForCapabilities(
  capabilities: QueryCapabilities,
  castAs: PlaintextKind,
): ColumnSchema['indexes'] {
  const indexes: ColumnSchema['indexes'] = {}

  // Text equality is always HMAC-based, so a text order domain (`string` +
  // order/range) still needs `unique`; numeric/date order domains answer
  // equality via `ob` and must NOT emit `unique`.
  if (
    capabilities.equality &&
    (!capabilities.orderAndRange || castAs === 'string')
  ) {
    indexes.unique = { token_filters: [] }
  }

  if (capabilities.orderAndRange) {
    indexes.ore = {}
  }

  if (capabilities.freeTextSearch) {
    // The factory returns fresh, unaliased nested objects per call, so no
    // column's emitted match block ever shares state with another's.
    indexes.match = defaultMatchOpts()
  }

  return indexes
}

/** Whether a domain's capabilities make it queryable at all (any flag set). */
function isQueryableCapabilities(capabilities: QueryCapabilities): boolean {
  return (
    capabilities.equality ||
    capabilities.orderAndRange ||
    capabilities.freeTextSearch
  )
}

/**
 * Shared base for every v3 concrete domain column. Parameterised by the FULL
 * literal {@link V3DomainDefinition} (not by capabilities alone): the private
 * `definition` field carries the literal `eqlType`/`castAs`/`capabilities`, so
 * two otherwise-empty subclasses (e.g. `EncryptedBoolColumn` and
 * `EncryptedDateColumn`, both storage-only) are NOT mutually assignable. This
 * nominality is what keeps plaintext inference precise.
 */
export class EncryptedV3Column<D extends V3DomainDefinition> {
  constructor(
    private readonly columnName: string,
    private readonly definition: D,
  ) {}

  getName(): string {
    return this.columnName
  }

  /** The concrete EQL v3 domain name. Metadata only; not emitted by `build()`. */
  getEqlType(): D['eqlType'] {
    return this.definition.eqlType
  }

  /** The semantic query capabilities this domain exposes. Metadata only. */
  getQueryCapabilities(): D['capabilities'] {
    return this.definition.capabilities
  }

  /** `true` when this domain can produce at least one kind of query term. */
  isQueryable(): QueryableFlag<D> {
    return isQueryableCapabilities(
      this.definition.capabilities,
    ) as QueryableFlag<D>
  }

  /** Emit the encrypt-config column: `cast_as` plus capability-derived indexes. */
  build(): ColumnSchema {
    return {
      cast_as: this.definition.castAs,
      indexes: indexesForCapabilities(
        this.definition.capabilities,
        this.definition.castAs,
      ),
    }
  }
}

const TEXT_SEARCH_DOMAIN = {
  eqlType: TEXT_SEARCH_EQL_TYPE,
  castAs: 'string',
  capabilities: TEXT_SEARCH,
} as const

/**
 * Builder for an `eql_v3.text_search` column.
 *
 * The concrete type inherently enables equality + order/range + free-text
 * match — there are no capability-enabling methods. `.freeTextSearch(opts?)`
 * tunes the match index only.
 *
 * NOTE — querying: a `text_search` column emits all three indexes (`unique`,
 * `ore`, `match`), and the shared index-inference picks them by fixed priority
 * `unique > match > ore`. So `encryptQuery(value, { column, table })` with NO
 * explicit `queryType` builds an EQUALITY term (via `unique`), NOT a free-text
 * match — a substring like `'joh'` then matches nothing. To run a free-text
 * match query you MUST pass `queryType: 'freeTextSearch'`:
 *
 * ```typescript
 * // equality (default): exact value only
 * client.encryptQuery('john@example.com', { column: users.email, table: users })
 * // free-text match: substring/token search
 * client.encryptQuery('joh', { column: users.email, table: users, queryType: 'freeTextSearch' })
 * ```
 */
export class EncryptedTextSearchColumn extends EncryptedV3Column<
  typeof TEXT_SEARCH_DOMAIN
> {
  private matchOpts: BuiltMatchIndexOpts

  constructor(columnName: string) {
    super(columnName, TEXT_SEARCH_DOMAIN)
    this.matchOpts = defaultMatchOpts()
  }

  /**
   * Tune the match index. Each provided key replaces its default; omitted
   * keys keep the default. This NEVER enables a capability — match is always
   * on for this type. Merge semantics mirror v2's `opts?.x ?? default`.
   */
  freeTextSearch(opts?: MatchIndexOpts): this {
    // Shared merge+clone (schema/match-defaults) — one source of truth with the
    // v2 `freeTextSearch()` builder. `resolveMatchOpts` merges each key over the
    // per-call defaults and deep-clones, so a caller mutating their own opts
    // object between `freeTextSearch(opts)` and `build()` cannot leak into the
    // emitted config (clone-on-write).
    this.matchOpts = resolveMatchOpts(opts)
    return this
  }

  /** Emit the encrypt-config column. Byte-identical to a v2 equality+order+match column. */
  override build(): ColumnSchema {
    // Derive `cast_as` + the `unique`/`ore` blocks from the shared
    // capability→index mapping (this domain's TEXT_SEARCH capabilities produce
    // exactly `{ unique, ore, match }`), then override ONLY `match` with this
    // builder's tuned opts. Hand-writing the unique/ore shape here would let it
    // silently drift from `indexesForCapabilities` — the exact divergence class
    // behind the text_ord `hm`-index bug. Deep-clone the match block so the
    // returned config never aliases this builder's internal `matchOpts`.
    const base = super.build()
    return {
      ...base,
      indexes: {
        ...base.indexes,
        match: cloneMatchOpts(this.matchOpts),
      },
    }
  }
}

// ---------------------------------------------------------------------------
// Concrete domain columns
//
// Every concrete class is an empty subclass parameterised by its literal domain
// definition (see EncryptedV3Column). The `types` namespace (see ./types)
// constructs these with the SAME literal constant so the instance's private
// `definition` field carries full literal type data — that is what keeps
// distinct domains nominally incompatible.
// ---------------------------------------------------------------------------

// int4
export class EncryptedInt4Column extends EncryptedV3Column<typeof INT4> {}
export class EncryptedInt4EqColumn extends EncryptedV3Column<typeof INT4_EQ> {}
export class EncryptedInt4OrdOreColumn extends EncryptedV3Column<
  typeof INT4_ORD_ORE
> {}
export class EncryptedInt4OrdColumn extends EncryptedV3Column<
  typeof INT4_ORD
> {}

// int2
export class EncryptedInt2Column extends EncryptedV3Column<typeof INT2> {}
export class EncryptedInt2EqColumn extends EncryptedV3Column<typeof INT2_EQ> {}
export class EncryptedInt2OrdOreColumn extends EncryptedV3Column<
  typeof INT2_ORD_ORE
> {}
export class EncryptedInt2OrdColumn extends EncryptedV3Column<
  typeof INT2_ORD
> {}

// int8 (bigint) domain builders are intentionally omitted pending FFI support
// for lossless bigint round-tripping — see the note by the INT4/DATE domain
// definitions above.

// date
export class EncryptedDateColumn extends EncryptedV3Column<typeof DATE> {}
export class EncryptedDateEqColumn extends EncryptedV3Column<typeof DATE_EQ> {}
export class EncryptedDateOrdOreColumn extends EncryptedV3Column<
  typeof DATE_ORD_ORE
> {}
export class EncryptedDateOrdColumn extends EncryptedV3Column<
  typeof DATE_ORD
> {}

// timestamp
export class EncryptedTimestampColumn extends EncryptedV3Column<
  typeof TIMESTAMP
> {}
export class EncryptedTimestampEqColumn extends EncryptedV3Column<
  typeof TIMESTAMP_EQ
> {}
export class EncryptedTimestampOrdOreColumn extends EncryptedV3Column<
  typeof TIMESTAMP_ORD_ORE
> {}
export class EncryptedTimestampOrdColumn extends EncryptedV3Column<
  typeof TIMESTAMP_ORD
> {}

// numeric
export class EncryptedNumericColumn extends EncryptedV3Column<typeof NUMERIC> {}
export class EncryptedNumericEqColumn extends EncryptedV3Column<
  typeof NUMERIC_EQ
> {}
export class EncryptedNumericOrdOreColumn extends EncryptedV3Column<
  typeof NUMERIC_ORD_ORE
> {}
export class EncryptedNumericOrdColumn extends EncryptedV3Column<
  typeof NUMERIC_ORD
> {}

// text (text_search is defined above with its match-tuning override)
export class EncryptedTextColumn extends EncryptedV3Column<typeof TEXT> {}
export class EncryptedTextEqColumn extends EncryptedV3Column<typeof TEXT_EQ> {}
export class EncryptedTextMatchColumn extends EncryptedV3Column<
  typeof TEXT_MATCH
> {}
export class EncryptedTextOrdOreColumn extends EncryptedV3Column<
  typeof TEXT_ORD_ORE
> {}
export class EncryptedTextOrdColumn extends EncryptedV3Column<
  typeof TEXT_ORD
> {}

// bool
export class EncryptedBoolColumn extends EncryptedV3Column<typeof BOOL> {}

// float4
export class EncryptedFloat4Column extends EncryptedV3Column<typeof FLOAT4> {}
export class EncryptedFloat4EqColumn extends EncryptedV3Column<
  typeof FLOAT4_EQ
> {}
export class EncryptedFloat4OrdOreColumn extends EncryptedV3Column<
  typeof FLOAT4_ORD_ORE
> {}
export class EncryptedFloat4OrdColumn extends EncryptedV3Column<
  typeof FLOAT4_ORD
> {}

// float8
export class EncryptedFloat8Column extends EncryptedV3Column<typeof FLOAT8> {}
export class EncryptedFloat8EqColumn extends EncryptedV3Column<
  typeof FLOAT8_EQ
> {}
export class EncryptedFloat8OrdOreColumn extends EncryptedV3Column<
  typeof FLOAT8_ORD_ORE
> {}
export class EncryptedFloat8OrdColumn extends EncryptedV3Column<
  typeof FLOAT8_ORD
> {}

/**
 * Union of every v3 concrete column type. Used as the value type for v3 table
 * columns so a table may mix any generated domains.
 */
export type AnyEncryptedV3Column =
  | EncryptedInt4Column
  | EncryptedInt4EqColumn
  | EncryptedInt4OrdOreColumn
  | EncryptedInt4OrdColumn
  | EncryptedInt2Column
  | EncryptedInt2EqColumn
  | EncryptedInt2OrdOreColumn
  | EncryptedInt2OrdColumn
  | EncryptedDateColumn
  | EncryptedDateEqColumn
  | EncryptedDateOrdOreColumn
  | EncryptedDateOrdColumn
  | EncryptedTimestampColumn
  | EncryptedTimestampEqColumn
  | EncryptedTimestampOrdOreColumn
  | EncryptedTimestampOrdColumn
  | EncryptedNumericColumn
  | EncryptedNumericEqColumn
  | EncryptedNumericOrdOreColumn
  | EncryptedNumericOrdColumn
  | EncryptedTextColumn
  | EncryptedTextEqColumn
  | EncryptedTextMatchColumn
  | EncryptedTextOrdOreColumn
  | EncryptedTextOrdColumn
  | EncryptedTextSearchColumn
  | EncryptedBoolColumn
  | EncryptedFloat4Column
  | EncryptedFloat4EqColumn
  | EncryptedFloat4OrdOreColumn
  | EncryptedFloat4OrdColumn
  | EncryptedFloat8Column
  | EncryptedFloat8EqColumn
  | EncryptedFloat8OrdOreColumn
  | EncryptedFloat8OrdColumn

/**
 * Shape of v3 table columns: every value is a v3 concrete column builder.
 * (Nested fields are deferred to later increments.)
 */
export type EncryptedV3TableColumn = {
  [key: string]: AnyEncryptedV3Column
}

/** Map a domain's {@link PlaintextKind} to its TypeScript plaintext type. */
type PlaintextFromKind<K extends PlaintextKind> = K extends 'string'
  ? string
  : K extends 'number'
    ? number
    : K extends 'boolean'
      ? boolean
      : K extends DateLikeCast
        ? Date
        : never

/**
 * The plaintext type for a single v3 column, read from the literal domain
 * definition carried on the base class's private field. This is stable across
 * empty subclasses that share the same base generic — a subclass-name
 * conditional would collapse because those subclasses are structurally
 * assignable to one another.
 */
export type PlaintextForColumn<C> =
  C extends EncryptedV3Column<infer D> ? PlaintextFromKind<D['castAs']> : never

/**
 * The user-facing `queryType` names a v3 column supports, derived 1:1 from its
 * capability flags. Resolves to `never` for a storage-only column (all flags
 * `false`) and for any non-v3 value. The names mirror the {@link QueryCapabilities}
 * keys and the first three {@link import('@/types').QueryTypeName} members.
 */
export type QueryTypesForColumn<C> =
  C extends EncryptedV3Column<infer D>
    ?
        | (D['capabilities']['equality'] extends true ? 'equality' : never)
        | (D['capabilities']['orderAndRange'] extends true
            ? 'orderAndRange'
            : never)
        | (D['capabilities']['freeTextSearch'] extends true
            ? 'freeTextSearch'
            : never)
    : never

/**
 * The concrete EQL v3 type string for a single column, read from the literal
 * domain definition carried on the base class's private field (mirrors
 * {@link PlaintextForColumn}). Distributes over a union of columns, so
 * `EqlTypeForColumn<AnyEncryptedV3Column>` yields the union of every domain's
 * `eqlType` — the canonical, source-of-truth key set for a type-driven test
 * matrix keyed by domain.
 */
export type EqlTypeForColumn<C> =
  C extends EncryptedV3Column<infer D> ? D['eqlType'] : never
