import type { ColumnSchema } from '@/schema'
import { defaultMatchOpts } from '@/schema/match-defaults'

/**
 * The query capabilities a v3 concrete domain exposes. These are SDK-facing
 * semantic flags describing what kinds of query terms a column can produce —
 * NOT the raw EQL index keys. They are metadata only and never emitted by
 * `build()`.
 *
 * - `equality`: exact-match lookups (EQL `hm`, or comparison via `ob`).
 * - `orderAndRange`: comparison / range lookups (EQL `op`, or `ob` on `_ord_ore` domains).
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
type PlaintextKind = 'string' | 'number' | 'bigint' | 'boolean' | DateLikeCast

/**
 * The full, literal definition of a v3 domain. This is the LOAD-BEARING type:
 * the base column class carries a private field of this type so that every
 * concrete (otherwise-empty) subclass is discriminated by its literal
 * `eqlType`/`castAs`/`capabilities` — TypeScript empty subclasses are NOT
 * nominal, so without this a storage-only `boolean` column would be assignable to
 * a storage-only `date` column and plaintext inference would collapse.
 */
type V3DomainDefinition = Readonly<{
  eqlType: `public.${string}`
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
export const TEXT_SEARCH_EQL_TYPE = 'public.eql_v3_text_search'

// Per-domain literal definitions. Each concrete column subclass is parameterised
// by `typeof <CONST>`; the literal `eqlType`/`castAs`/`capabilities` on each is
// what makes the otherwise-empty subclasses nominally distinct (see
// V3DomainDefinition). Order mirrors eql-bindings `CATALOG` order.
//
// Exported for the `types` namespace factory (see ./types); they are internal
// building blocks and are intentionally NOT re-exported from the public barrel.
export const INTEGER = {
  eqlType: 'public.eql_v3_integer',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const INTEGER_EQ = {
  eqlType: 'public.eql_v3_integer_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const INTEGER_ORD_ORE = {
  eqlType: 'public.eql_v3_integer_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const INTEGER_ORD = {
  eqlType: 'public.eql_v3_integer_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const SMALLINT = {
  eqlType: 'public.eql_v3_smallint',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const SMALLINT_EQ = {
  eqlType: 'public.eql_v3_smallint_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const SMALLINT_ORD_ORE = {
  eqlType: 'public.eql_v3_smallint_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const SMALLINT_ORD = {
  eqlType: 'public.eql_v3_smallint_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

// bigint (int8) domains. Plaintext is a JS `bigint` (always decrypts to
// `bigint`); bounds are the full i64 range. protect-ffi round-trips an in-range
// native bigint losslessly, and values outside the signed 64-bit range are
// rejected client-side by `assertValidNumericValue` before they reach the FFI
// (`*_ord_ope` variants are out of scope — CIP-3403.)
export const BIGINT = {
  eqlType: 'public.eql_v3_bigint',
  castAs: 'bigint',
  capabilities: STORAGE_ONLY,
} as const
export const BIGINT_EQ = {
  eqlType: 'public.eql_v3_bigint_eq',
  castAs: 'bigint',
  capabilities: EQUALITY_ONLY,
} as const
export const BIGINT_ORD_ORE = {
  eqlType: 'public.eql_v3_bigint_ord_ore',
  castAs: 'bigint',
  capabilities: ORDER_AND_RANGE,
} as const
export const BIGINT_ORD = {
  eqlType: 'public.eql_v3_bigint_ord',
  castAs: 'bigint',
  capabilities: ORDER_AND_RANGE,
} as const

export const DATE = {
  eqlType: 'public.eql_v3_date',
  castAs: 'date',
  capabilities: STORAGE_ONLY,
} as const
export const DATE_EQ = {
  eqlType: 'public.eql_v3_date_eq',
  castAs: 'date',
  capabilities: EQUALITY_ONLY,
} as const
export const DATE_ORD_ORE = {
  eqlType: 'public.eql_v3_date_ord_ore',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const
export const DATE_ORD = {
  eqlType: 'public.eql_v3_date_ord',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const

export const TIMESTAMP = {
  eqlType: 'public.eql_v3_timestamp',
  castAs: 'timestamp',
  capabilities: STORAGE_ONLY,
} as const
export const TIMESTAMP_EQ = {
  eqlType: 'public.eql_v3_timestamp_eq',
  castAs: 'timestamp',
  capabilities: EQUALITY_ONLY,
} as const
export const TIMESTAMP_ORD_ORE = {
  eqlType: 'public.eql_v3_timestamp_ord_ore',
  castAs: 'timestamp',
  capabilities: ORDER_AND_RANGE,
} as const
export const TIMESTAMP_ORD = {
  eqlType: 'public.eql_v3_timestamp_ord',
  castAs: 'timestamp',
  capabilities: ORDER_AND_RANGE,
} as const

export const NUMERIC = {
  eqlType: 'public.eql_v3_numeric',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const NUMERIC_EQ = {
  eqlType: 'public.eql_v3_numeric_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const NUMERIC_ORD_ORE = {
  eqlType: 'public.eql_v3_numeric_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const NUMERIC_ORD = {
  eqlType: 'public.eql_v3_numeric_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const TEXT = {
  eqlType: 'public.eql_v3_text',
  castAs: 'string',
  capabilities: STORAGE_ONLY,
} as const
export const TEXT_EQ = {
  eqlType: 'public.eql_v3_text_eq',
  castAs: 'string',
  capabilities: EQUALITY_ONLY,
} as const
export const TEXT_MATCH = {
  eqlType: 'public.eql_v3_text_match',
  castAs: 'string',
  capabilities: MATCH_ONLY,
} as const
export const TEXT_ORD_ORE = {
  eqlType: 'public.eql_v3_text_ord_ore',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const
export const TEXT_ORD = {
  eqlType: 'public.eql_v3_text_ord',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const

export const BOOLEAN = {
  eqlType: 'public.eql_v3_boolean',
  castAs: 'boolean',
  capabilities: STORAGE_ONLY,
} as const

export const REAL = {
  eqlType: 'public.eql_v3_real',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const REAL_EQ = {
  eqlType: 'public.eql_v3_real_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const REAL_ORD_ORE = {
  eqlType: 'public.eql_v3_real_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const REAL_ORD = {
  eqlType: 'public.eql_v3_real_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

export const DOUBLE = {
  eqlType: 'public.eql_v3_double',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
export const DOUBLE_EQ = {
  eqlType: 'public.eql_v3_double_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
export const DOUBLE_ORD_ORE = {
  eqlType: 'public.eql_v3_double_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
export const DOUBLE_ORD = {
  eqlType: 'public.eql_v3_double_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

/**
 * Translate a domain's semantic {@link QueryCapabilities} (plus its plaintext
 * `castAs`, which decides how equality is answered, and its ordering flavour)
 * into the concrete EQL index block emitted by `build()`.
 *
 * - `unique` (the `hm` HMAC index) whenever equality is answered via HMAC:
 *   equality-only domains of ANY type, AND text order domains. Text equality is
 *   HMAC-based — the `public.eql_v3_text_ord` / `public.eql_v3_text_ord_ore` SQL domains
 *   REQUIRE `hm` in the stored ciphertext (their `eql_v3.eq_term` extracts it).
 * - ONE ordering index for any order/range domain, selected by the domain's
 *   name (eql-3.0.0): plain `_ord` domains (and `text_search`) are OPE-backed —
 *   `ope`, the `op` CLLW-OPE term — while `_ord_ore` domains keep block-ORE —
 *   `ore`, the `ob` term. The two terms are not cross-comparable, and each
 *   domain's SQL CHECK requires exactly its own. For numeric/date order
 *   domains the ordering term also answers equality (via the SQL `=`
 *   operator), so those emit no `hm`. Text order domains emit BOTH `unique`
 *   and the ordering index.
 * - `match` (the `bf` bloom-filter index) for free-text search, deep-cloned from
 *   the per-call defaults so no nested object is ever shared across columns, and
 *   emitted with `include_original: false` (see below).
 */
function indexesForCapabilities(
  capabilities: QueryCapabilities,
  castAs: PlaintextKind,
  ordering: 'ope' | 'ore',
): ColumnSchema['indexes'] {
  const indexes: ColumnSchema['indexes'] = {}

  // Text equality is always HMAC-based, so a text order domain (`string` +
  // order/range) still needs `unique`; numeric/date order domains answer
  // equality via their ordering term and must NOT emit `unique`.
  if (
    capabilities.equality &&
    (!capabilities.orderAndRange || castAs === 'string')
  ) {
    indexes.unique = { token_filters: [] }
  }

  if (capabilities.orderAndRange) {
    indexes[ordering] = {}
  }

  if (capabilities.freeTextSearch) {
    // The factory returns fresh, unaliased nested objects per call, so no
    // column's emitted match block ever shares state with another's.
    //
    // `include_original` is overridden off the v2 builder's `true`. protect-ffi
    // ignores the flag entirely (measured across 0.24 and 0.29, EQL v2 and v3:
    // the emitted bloom is trigram-only either way, and a value shorter than
    // `token_length` blooms to nothing regardless), so this is inert today. It
    // is set to the value a substring-search domain actually wants — matching
    // the zod schema's own default — so that a protect-ffi release which starts
    // honouring the flag cannot silently break `contains`.
    indexes.match = { ...defaultMatchOpts(), include_original: false }
  }

  return indexes
}

/**
 * The ordering flavour a domain's name pins (eql-3.0.0): `_ord_ore` domains
 * are block-ORE (`ore` index, `ob` term); every other ordering domain —
 * `_ord` and `text_search` — is CLLW-OPE (`ope` index, `op` term).
 */
function orderingForEqlType(eqlType: string): 'ope' | 'ore' {
  return eqlType.endsWith('_ord_ore') ? 'ore' : 'ope'
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
 * two otherwise-empty subclasses (e.g. `EncryptedBooleanColumn` and
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
        orderingForEqlType(this.definition.eqlType),
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
 * Builder for a `public.eql_v3_text_search` column.
 *
 * The concrete type inherently enables equality + order/range + free-text
 * match — there are no capability-enabling or tuning methods. The match index
 * is always emitted with the default configuration.
 *
 * NOTE — querying: a `text_search` column emits all three indexes (`unique`,
 * `ope`, `match`), and the shared index-inference picks them by fixed priority
 * `unique > match > ordering`. So `encryptQuery(value, { column, table })` with NO
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
  constructor(columnName: string) {
    super(columnName, TEXT_SEARCH_DOMAIN)
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

// integer
export class EncryptedIntegerColumn extends EncryptedV3Column<typeof INTEGER> {}
export class EncryptedIntegerEqColumn extends EncryptedV3Column<
  typeof INTEGER_EQ
> {}
export class EncryptedIntegerOrdOreColumn extends EncryptedV3Column<
  typeof INTEGER_ORD_ORE
> {}
export class EncryptedIntegerOrdColumn extends EncryptedV3Column<
  typeof INTEGER_ORD
> {}

// smallint
export class EncryptedSmallintColumn extends EncryptedV3Column<
  typeof SMALLINT
> {}
export class EncryptedSmallintEqColumn extends EncryptedV3Column<
  typeof SMALLINT_EQ
> {}
export class EncryptedSmallintOrdOreColumn extends EncryptedV3Column<
  typeof SMALLINT_ORD_ORE
> {}
export class EncryptedSmallintOrdColumn extends EncryptedV3Column<
  typeof SMALLINT_ORD
> {}

// bigint (int8) — plaintext is a JS `bigint`, round-tripped losslessly by the
// native protect-ffi boundary (see the BIGINT domain definitions above).
export class EncryptedBigintColumn extends EncryptedV3Column<typeof BIGINT> {}
export class EncryptedBigintEqColumn extends EncryptedV3Column<
  typeof BIGINT_EQ
> {}
export class EncryptedBigintOrdOreColumn extends EncryptedV3Column<
  typeof BIGINT_ORD_ORE
> {}
export class EncryptedBigintOrdColumn extends EncryptedV3Column<
  typeof BIGINT_ORD
> {}

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

// boolean
export class EncryptedBooleanColumn extends EncryptedV3Column<typeof BOOLEAN> {}

// real
export class EncryptedRealColumn extends EncryptedV3Column<typeof REAL> {}
export class EncryptedRealEqColumn extends EncryptedV3Column<typeof REAL_EQ> {}
export class EncryptedRealOrdOreColumn extends EncryptedV3Column<
  typeof REAL_ORD_ORE
> {}
export class EncryptedRealOrdColumn extends EncryptedV3Column<
  typeof REAL_ORD
> {}

// double
export class EncryptedDoubleColumn extends EncryptedV3Column<typeof DOUBLE> {}
export class EncryptedDoubleEqColumn extends EncryptedV3Column<
  typeof DOUBLE_EQ
> {}
export class EncryptedDoubleOrdOreColumn extends EncryptedV3Column<
  typeof DOUBLE_ORD_ORE
> {}
export class EncryptedDoubleOrdColumn extends EncryptedV3Column<
  typeof DOUBLE_ORD
> {}

/**
 * Union of every v3 concrete column type. Used as the value type for v3 table
 * columns so a table may mix any generated domains.
 */
export type AnyEncryptedV3Column =
  | EncryptedIntegerColumn
  | EncryptedIntegerEqColumn
  | EncryptedIntegerOrdOreColumn
  | EncryptedIntegerOrdColumn
  | EncryptedSmallintColumn
  | EncryptedSmallintEqColumn
  | EncryptedSmallintOrdOreColumn
  | EncryptedSmallintOrdColumn
  | EncryptedBigintColumn
  | EncryptedBigintEqColumn
  | EncryptedBigintOrdOreColumn
  | EncryptedBigintOrdColumn
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
  | EncryptedBooleanColumn
  | EncryptedRealColumn
  | EncryptedRealEqColumn
  | EncryptedRealOrdOreColumn
  | EncryptedRealOrdColumn
  | EncryptedDoubleColumn
  | EncryptedDoubleEqColumn
  | EncryptedDoubleOrdOreColumn
  | EncryptedDoubleOrdColumn

/**
 * A factory that builds a concrete v3 column for a given DB column name.
 *
 * Declared here rather than beside `DOMAIN_REGISTRY` so that `./types` can
 * constrain its own export against it without importing from `./domain-registry`,
 * which imports `./types` back as a value.
 */
export type V3ColumnFactory = (name: string) => AnyEncryptedV3Column

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
    : K extends 'bigint'
      ? bigint
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
