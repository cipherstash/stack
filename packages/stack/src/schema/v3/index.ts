import type { ColumnSchema, EncryptConfig, MatchIndexOpts } from '@/schema'
import type { Encrypted } from '@/types'

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

/** The plaintext (TypeScript) kind a v3 domain decrypts to. A subset of the
 * SDK `CastAs` enum, restricted to the scalar kinds v3 domains actually use. */
type PlaintextKind = 'string' | 'number' | 'boolean' | 'date'

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
const INT4 = {
  eqlType: 'eql_v3.int4',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
const INT4_EQ = {
  eqlType: 'eql_v3.int4_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
const INT4_ORD_ORE = {
  eqlType: 'eql_v3.int4_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
const INT4_ORD = {
  eqlType: 'eql_v3.int4_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

const INT2 = {
  eqlType: 'eql_v3.int2',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
const INT2_EQ = {
  eqlType: 'eql_v3.int2_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
const INT2_ORD_ORE = {
  eqlType: 'eql_v3.int2_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
const INT2_ORD = {
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

const DATE = {
  eqlType: 'eql_v3.date',
  castAs: 'date',
  capabilities: STORAGE_ONLY,
} as const
const DATE_EQ = {
  eqlType: 'eql_v3.date_eq',
  castAs: 'date',
  capabilities: EQUALITY_ONLY,
} as const
const DATE_ORD_ORE = {
  eqlType: 'eql_v3.date_ord_ore',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const
const DATE_ORD = {
  eqlType: 'eql_v3.date_ord',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const

const TIMESTAMPTZ = {
  eqlType: 'eql_v3.timestamptz',
  castAs: 'date',
  capabilities: STORAGE_ONLY,
} as const
const TIMESTAMPTZ_EQ = {
  eqlType: 'eql_v3.timestamptz_eq',
  castAs: 'date',
  capabilities: EQUALITY_ONLY,
} as const
const TIMESTAMPTZ_ORD_ORE = {
  eqlType: 'eql_v3.timestamptz_ord_ore',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const
const TIMESTAMPTZ_ORD = {
  eqlType: 'eql_v3.timestamptz_ord',
  castAs: 'date',
  capabilities: ORDER_AND_RANGE,
} as const

const NUMERIC = {
  eqlType: 'eql_v3.numeric',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
const NUMERIC_EQ = {
  eqlType: 'eql_v3.numeric_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
const NUMERIC_ORD_ORE = {
  eqlType: 'eql_v3.numeric_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
const NUMERIC_ORD = {
  eqlType: 'eql_v3.numeric_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

const TEXT = {
  eqlType: 'eql_v3.text',
  castAs: 'string',
  capabilities: STORAGE_ONLY,
} as const
const TEXT_EQ = {
  eqlType: 'eql_v3.text_eq',
  castAs: 'string',
  capabilities: EQUALITY_ONLY,
} as const
const TEXT_MATCH = {
  eqlType: 'eql_v3.text_match',
  castAs: 'string',
  capabilities: MATCH_ONLY,
} as const
const TEXT_ORD_ORE = {
  eqlType: 'eql_v3.text_ord_ore',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const
const TEXT_ORD = {
  eqlType: 'eql_v3.text_ord',
  castAs: 'string',
  capabilities: ORDER_AND_RANGE,
} as const

const BOOL = {
  eqlType: 'eql_v3.bool',
  castAs: 'boolean',
  capabilities: STORAGE_ONLY,
} as const

const FLOAT4 = {
  eqlType: 'eql_v3.float4',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
const FLOAT4_EQ = {
  eqlType: 'eql_v3.float4_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
const FLOAT4_ORD_ORE = {
  eqlType: 'eql_v3.float4_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
const FLOAT4_ORD = {
  eqlType: 'eql_v3.float4_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

const FLOAT8 = {
  eqlType: 'eql_v3.float8',
  castAs: 'number',
  capabilities: STORAGE_ONLY,
} as const
const FLOAT8_EQ = {
  eqlType: 'eql_v3.float8_eq',
  castAs: 'number',
  capabilities: EQUALITY_ONLY,
} as const
const FLOAT8_ORD_ORE = {
  eqlType: 'eql_v3.float8_ord_ore',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const
const FLOAT8_ORD = {
  eqlType: 'eql_v3.float8_ord',
  castAs: 'number',
  capabilities: ORDER_AND_RANGE,
} as const

/**
 * Fully-resolved match-index options: every field present and non-`undefined`.
 *
 * `MatchIndexOpts` (the user-facing tuning input) has all fields optional —
 * each is `.default(...).optional()` in the zod schema, so its inferred type is
 * `T | undefined`. This type pins the BUILT/resolved shape explicitly via
 * `NonNullable<...>`, which states the non-null intent directly and is robust
 * regardless of `Required<>`'s subtle, `exactOptionalPropertyTypes`-dependent
 * stripping semantics. (v2 uses `Required<MatchIndexOpts>` and that compiles
 * fine under this repo's tsconfig — `strict: true`, NO `exactOptionalPropertyTypes`
 * — so this is a clarity/robustness choice, not a fix for a present break.)
 */
type BuiltMatchIndexOpts = {
  tokenizer: NonNullable<MatchIndexOpts['tokenizer']>
  token_filters: NonNullable<MatchIndexOpts['token_filters']>
  k: NonNullable<MatchIndexOpts['k']>
  m: NonNullable<MatchIndexOpts['m']>
  include_original: NonNullable<MatchIndexOpts['include_original']>
}

/**
 * Default match-index parameters. These mirror the v2 `freeTextSearch()`
 * builder defaults EXACTLY (note `include_original: true`, which is the v2
 * builder default rather than the zod-schema default of `false`).
 *
 * This is a FACTORY (not a shared `const`) so every caller gets fresh, unaliased
 * nested objects (`tokenizer`, `token_filters` and the `{ kind: 'downcase' }`
 * inside it). A shared const would be shallow-copied by `{ ...DEFAULT }`, leaving
 * those nested objects aliased across every column — a caller mutating one built
 * config could then corrupt the defaults used by later columns.
 */
function defaultMatchOpts(): BuiltMatchIndexOpts {
  return {
    tokenizer: { kind: 'ngram', token_length: 3 },
    token_filters: [{ kind: 'downcase' }],
    k: 6,
    m: 2048,
    include_original: true,
  }
}

/**
 * Translate a domain's semantic {@link QueryCapabilities} into the concrete EQL
 * index block emitted by `build()`.
 *
 * - equality WITHOUT order/range → `unique` (the `hm` HMAC index).
 * - order/range → `ore` ONLY. The EQL `ob` key supports both equality and
 *   range, so an order-capable column does NOT also emit `unique`.
 * - free-text search → `match` (the `bf` bloom-filter index), deep-cloned from
 *   the per-call defaults so no nested object is ever shared across columns.
 */
function indexesForCapabilities(
  capabilities: QueryCapabilities,
): ColumnSchema['indexes'] {
  const indexes: ColumnSchema['indexes'] = {}

  if (capabilities.equality && !capabilities.orderAndRange) {
    indexes.unique = { token_filters: [] }
  }

  if (capabilities.orderAndRange) {
    indexes.ore = {}
  }

  if (capabilities.freeTextSearch) {
    const match = defaultMatchOpts()
    indexes.match = {
      ...match,
      tokenizer: { ...match.tokenizer },
      token_filters: match.token_filters.map((f) => ({ ...f })),
    }
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
class EncryptedV3Column<D extends V3DomainDefinition> {
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
      indexes: indexesForCapabilities(this.definition.capabilities),
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
    // A fresh defaults object per call supplies the `?? ` fallbacks, so no
    // nested default object is ever shared into `this.matchOpts` by reference.
    const defaults = defaultMatchOpts()
    // Clone-on-write: deep-copy the nested tokenizer / token_filters when
    // storing them so a caller mutating their own opts object between
    // freeTextSearch(opts) and build() cannot leak into the emitted config.
    const tokenizer = opts?.tokenizer ?? defaults.tokenizer
    const token_filters = opts?.token_filters ?? defaults.token_filters
    this.matchOpts = {
      tokenizer: { ...tokenizer },
      token_filters: token_filters.map((f) => ({ ...f })),
      k: opts?.k ?? defaults.k,
      m: opts?.m ?? defaults.m,
      include_original: opts?.include_original ?? defaults.include_original,
    }
    return this
  }

  /** Emit the encrypt-config column. Byte-identical to a v2 equality+order+match column. */
  override build(): ColumnSchema {
    // Deep-clone the match block so the returned config NEVER aliases this
    // builder's internal `matchOpts` (or any caller-supplied opts merged into
    // it). A caller mutating the returned object cannot corrupt this builder's
    // state or another column's defaults.
    return {
      cast_as: 'string',
      indexes: {
        unique: { token_filters: [] },
        ore: {},
        match: {
          ...this.matchOpts,
          tokenizer: { ...this.matchOpts.tokenizer },
          token_filters: this.matchOpts.token_filters.map((f) => ({ ...f })),
        },
      },
    }
  }
}

/**
 * Define an `eql_v3.text_search` column. The concrete type carries all three
 * capabilities (equality + order/range + free-text match). Chain
 * `.freeTextSearch(opts)` to tune the match index.
 *
 * Querying defaults to EQUALITY — pass `queryType: 'freeTextSearch'` to
 * `encryptQuery` for free-text match. See {@link EncryptedTextSearchColumn}.
 */
export function encryptedTextSearchColumn(
  columnName: string,
): EncryptedTextSearchColumn {
  return new EncryptedTextSearchColumn(columnName)
}

// ---------------------------------------------------------------------------
// Concrete domain columns and builders
//
// Every concrete class is an empty subclass parameterised by its literal domain
// definition (see EncryptedV3Column). The paired builder passes the SAME literal
// constant so the instance's private `definition` field carries full literal
// type data — that is what keeps distinct domains nominally incompatible.
// ---------------------------------------------------------------------------

// int4
export class EncryptedInt4Column extends EncryptedV3Column<typeof INT4> {}
export const encryptedInt4Column = (columnName: string) =>
  new EncryptedInt4Column(columnName, INT4)

export class EncryptedInt4EqColumn extends EncryptedV3Column<typeof INT4_EQ> {}
export const encryptedInt4EqColumn = (columnName: string) =>
  new EncryptedInt4EqColumn(columnName, INT4_EQ)

export class EncryptedInt4OrdOreColumn extends EncryptedV3Column<
  typeof INT4_ORD_ORE
> {}
export const encryptedInt4OrdOreColumn = (columnName: string) =>
  new EncryptedInt4OrdOreColumn(columnName, INT4_ORD_ORE)

export class EncryptedInt4OrdColumn extends EncryptedV3Column<
  typeof INT4_ORD
> {}
export const encryptedInt4OrdColumn = (columnName: string) =>
  new EncryptedInt4OrdColumn(columnName, INT4_ORD)

// int2
export class EncryptedInt2Column extends EncryptedV3Column<typeof INT2> {}
export const encryptedInt2Column = (columnName: string) =>
  new EncryptedInt2Column(columnName, INT2)

export class EncryptedInt2EqColumn extends EncryptedV3Column<typeof INT2_EQ> {}
export const encryptedInt2EqColumn = (columnName: string) =>
  new EncryptedInt2EqColumn(columnName, INT2_EQ)

export class EncryptedInt2OrdOreColumn extends EncryptedV3Column<
  typeof INT2_ORD_ORE
> {}
export const encryptedInt2OrdOreColumn = (columnName: string) =>
  new EncryptedInt2OrdOreColumn(columnName, INT2_ORD_ORE)

export class EncryptedInt2OrdColumn extends EncryptedV3Column<
  typeof INT2_ORD
> {}
export const encryptedInt2OrdColumn = (columnName: string) =>
  new EncryptedInt2OrdColumn(columnName, INT2_ORD)

// int8 (bigint) domain builders are intentionally omitted pending FFI support
// for lossless bigint round-tripping — see the note by the INT4/DATE domain
// definitions above.

// date
export class EncryptedDateColumn extends EncryptedV3Column<typeof DATE> {}
export const encryptedDateColumn = (columnName: string) =>
  new EncryptedDateColumn(columnName, DATE)

export class EncryptedDateEqColumn extends EncryptedV3Column<typeof DATE_EQ> {}
export const encryptedDateEqColumn = (columnName: string) =>
  new EncryptedDateEqColumn(columnName, DATE_EQ)

export class EncryptedDateOrdOreColumn extends EncryptedV3Column<
  typeof DATE_ORD_ORE
> {}
export const encryptedDateOrdOreColumn = (columnName: string) =>
  new EncryptedDateOrdOreColumn(columnName, DATE_ORD_ORE)

export class EncryptedDateOrdColumn extends EncryptedV3Column<
  typeof DATE_ORD
> {}
export const encryptedDateOrdColumn = (columnName: string) =>
  new EncryptedDateOrdColumn(columnName, DATE_ORD)

// timestamptz
export class EncryptedTimestamptzColumn extends EncryptedV3Column<
  typeof TIMESTAMPTZ
> {}
export const encryptedTimestamptzColumn = (columnName: string) =>
  new EncryptedTimestamptzColumn(columnName, TIMESTAMPTZ)

export class EncryptedTimestamptzEqColumn extends EncryptedV3Column<
  typeof TIMESTAMPTZ_EQ
> {}
export const encryptedTimestamptzEqColumn = (columnName: string) =>
  new EncryptedTimestamptzEqColumn(columnName, TIMESTAMPTZ_EQ)

export class EncryptedTimestamptzOrdOreColumn extends EncryptedV3Column<
  typeof TIMESTAMPTZ_ORD_ORE
> {}
export const encryptedTimestamptzOrdOreColumn = (columnName: string) =>
  new EncryptedTimestamptzOrdOreColumn(columnName, TIMESTAMPTZ_ORD_ORE)

export class EncryptedTimestamptzOrdColumn extends EncryptedV3Column<
  typeof TIMESTAMPTZ_ORD
> {}
export const encryptedTimestamptzOrdColumn = (columnName: string) =>
  new EncryptedTimestamptzOrdColumn(columnName, TIMESTAMPTZ_ORD)

// numeric
export class EncryptedNumericColumn extends EncryptedV3Column<typeof NUMERIC> {}
export const encryptedNumericColumn = (columnName: string) =>
  new EncryptedNumericColumn(columnName, NUMERIC)

export class EncryptedNumericEqColumn extends EncryptedV3Column<
  typeof NUMERIC_EQ
> {}
export const encryptedNumericEqColumn = (columnName: string) =>
  new EncryptedNumericEqColumn(columnName, NUMERIC_EQ)

export class EncryptedNumericOrdOreColumn extends EncryptedV3Column<
  typeof NUMERIC_ORD_ORE
> {}
export const encryptedNumericOrdOreColumn = (columnName: string) =>
  new EncryptedNumericOrdOreColumn(columnName, NUMERIC_ORD_ORE)

export class EncryptedNumericOrdColumn extends EncryptedV3Column<
  typeof NUMERIC_ORD
> {}
export const encryptedNumericOrdColumn = (columnName: string) =>
  new EncryptedNumericOrdColumn(columnName, NUMERIC_ORD)

// text (text_search stays defined above with its match-tuning override)
export class EncryptedTextColumn extends EncryptedV3Column<typeof TEXT> {}
export const encryptedTextColumn = (columnName: string) =>
  new EncryptedTextColumn(columnName, TEXT)

export class EncryptedTextEqColumn extends EncryptedV3Column<typeof TEXT_EQ> {}
export const encryptedTextEqColumn = (columnName: string) =>
  new EncryptedTextEqColumn(columnName, TEXT_EQ)

export class EncryptedTextMatchColumn extends EncryptedV3Column<
  typeof TEXT_MATCH
> {}
export const encryptedTextMatchColumn = (columnName: string) =>
  new EncryptedTextMatchColumn(columnName, TEXT_MATCH)

export class EncryptedTextOrdOreColumn extends EncryptedV3Column<
  typeof TEXT_ORD_ORE
> {}
export const encryptedTextOrdOreColumn = (columnName: string) =>
  new EncryptedTextOrdOreColumn(columnName, TEXT_ORD_ORE)

export class EncryptedTextOrdColumn extends EncryptedV3Column<
  typeof TEXT_ORD
> {}
export const encryptedTextOrdColumn = (columnName: string) =>
  new EncryptedTextOrdColumn(columnName, TEXT_ORD)

// bool
export class EncryptedBoolColumn extends EncryptedV3Column<typeof BOOL> {}
export const encryptedBoolColumn = (columnName: string) =>
  new EncryptedBoolColumn(columnName, BOOL)

// float4
export class EncryptedFloat4Column extends EncryptedV3Column<typeof FLOAT4> {}
export const encryptedFloat4Column = (columnName: string) =>
  new EncryptedFloat4Column(columnName, FLOAT4)

export class EncryptedFloat4EqColumn extends EncryptedV3Column<
  typeof FLOAT4_EQ
> {}
export const encryptedFloat4EqColumn = (columnName: string) =>
  new EncryptedFloat4EqColumn(columnName, FLOAT4_EQ)

export class EncryptedFloat4OrdOreColumn extends EncryptedV3Column<
  typeof FLOAT4_ORD_ORE
> {}
export const encryptedFloat4OrdOreColumn = (columnName: string) =>
  new EncryptedFloat4OrdOreColumn(columnName, FLOAT4_ORD_ORE)

export class EncryptedFloat4OrdColumn extends EncryptedV3Column<
  typeof FLOAT4_ORD
> {}
export const encryptedFloat4OrdColumn = (columnName: string) =>
  new EncryptedFloat4OrdColumn(columnName, FLOAT4_ORD)

// float8
export class EncryptedFloat8Column extends EncryptedV3Column<typeof FLOAT8> {}
export const encryptedFloat8Column = (columnName: string) =>
  new EncryptedFloat8Column(columnName, FLOAT8)

export class EncryptedFloat8EqColumn extends EncryptedV3Column<
  typeof FLOAT8_EQ
> {}
export const encryptedFloat8EqColumn = (columnName: string) =>
  new EncryptedFloat8EqColumn(columnName, FLOAT8_EQ)

export class EncryptedFloat8OrdOreColumn extends EncryptedV3Column<
  typeof FLOAT8_ORD_ORE
> {}
export const encryptedFloat8OrdOreColumn = (columnName: string) =>
  new EncryptedFloat8OrdOreColumn(columnName, FLOAT8_ORD_ORE)

export class EncryptedFloat8OrdColumn extends EncryptedV3Column<
  typeof FLOAT8_ORD
> {}
export const encryptedFloat8OrdColumn = (columnName: string) =>
  new EncryptedFloat8OrdColumn(columnName, FLOAT8_ORD)

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
  | EncryptedTimestamptzColumn
  | EncryptedTimestamptzEqColumn
  | EncryptedTimestamptzOrdOreColumn
  | EncryptedTimestamptzOrdColumn
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

interface TableDefinition {
  tableName: string
  columns: Record<string, ColumnSchema>
}

/**
 * A v3 encrypted table. Mirrors the v2 `EncryptedTable` but only accepts v3
 * column builders. Emits the same `{ tableName, columns }` definition shape.
 */
export class EncryptedTable<T extends EncryptedV3TableColumn> {
  /** @internal Type-level brand so TypeScript can infer `T` from `EncryptedTable<T>`. */
  declare readonly _columnType: T

  constructor(
    public readonly tableName: string,
    public readonly columnBuilders: T,
  ) {}

  build(): TableDefinition {
    const builtColumns: Record<string, ColumnSchema> = {}
    for (const builder of Object.values(this.columnBuilders)) {
      // Key by the column's DB name (`getName()`), NOT the JS property name.
      // `encrypt`/`decrypt` look columns up in the config by `column.getName()`,
      // so a camelCase JS key mapping to a snake_case DB column (e.g.
      // `createdOn: encryptedDateColumn('created_on')`) must register under
      // `created_on` or the FFI reports "column not found in Encrypt config".
      builtColumns[builder.getName()] = builder.build()
    }
    return {
      tableName: this.tableName,
      columns: builtColumns,
    }
  }

  /**
   * Map each column's JS property name to its DB column name (`getName()`).
   * The model path matches user models by property name but must address the
   * encrypt config and FFI by DB name — `build()` keys columns by DB name, so
   * the two only agree when property == name. This recovers the mapping that
   * `build()` discards.
   */
  buildColumnKeyMap(): Record<string, string> {
    const map: Record<string, string> = {}
    for (const [property, builder] of Object.entries(this.columnBuilders)) {
      map[property] = builder.getName()
    }
    return map
  }
}

/**
 * Own instance members of {@link EncryptedTable} that a column name must not
 * shadow. Because {@link encryptedTable} copies column builders onto the
 * instance for accessor access (`users.email`), a column named e.g. `build`
 * would otherwise overwrite the method that {@link buildEncryptConfig} relies
 * on. `_columnType` is a type-only `declare` (no runtime property) so it is
 * listed explicitly here rather than caught by the `in` check below.
 */
const RESERVED_TABLE_KEYS = new Set([
  'tableName',
  'columnBuilders',
  '_columnType',
  'build',
  'buildColumnKeyMap',
])

/**
 * Whether a column name would collide with a reserved property on the table
 * object — either an own member ({@link RESERVED_TABLE_KEYS}) or any inherited
 * `Object.prototype` member (`constructor`, `toString`, `valueOf`,
 * `hasOwnProperty`, …). The `in` check covers the prototype chain so assigning
 * the column as an own property can never shadow a prototype method/accessor.
 */
function isReservedTableKey(tableBuilder: object, colName: string): boolean {
  return RESERVED_TABLE_KEYS.has(colName) || colName in tableBuilder
}

/**
 * Define a v3 encrypted table. Intentionally shadows the v2 `encryptedTable`
 * name but lives on the `/v3` subpath — the importer picks the model by import
 * path. The returned object is also a column accessor (`users.email`).
 */
export function encryptedTable<T extends EncryptedV3TableColumn>(
  tableName: string,
  columns: T,
): EncryptedTable<T> & T {
  const tableBuilder = new EncryptedTable(
    tableName,
    columns,
  ) as EncryptedTable<T> & T

  for (const [colName, colBuilder] of Object.entries(columns)) {
    if (isReservedTableKey(tableBuilder, colName)) {
      throw new Error(
        `Column name "${colName}" collides with a reserved EncryptedTable property`,
      )
    }
    ;(tableBuilder as EncryptedV3TableColumn)[colName] = colBuilder
  }

  return tableBuilder
}

/**
 * Build an `EncryptConfig` (`v: 1`) from one or more v3 tables. Emits the same
 * shape as v2's `buildEncryptConfig`.
 */
export function buildEncryptConfig(
  ...tables: Array<EncryptedTable<EncryptedV3TableColumn>>
): EncryptConfig {
  const config: EncryptConfig = {
    v: 1,
    tables: {},
  }

  for (const tb of tables) {
    const tableDef = tb.build()
    // Config tables are keyed by name, so a duplicate would silently overwrite
    // the earlier table. Fail loudly instead. (v3-only additive guard; v2's
    // buildEncryptConfig keeps its existing silent-overwrite behavior.)
    if (Object.hasOwn(config.tables, tableDef.tableName)) {
      throw new Error(
        `[schema/v3]: duplicate table name "${tableDef.tableName}" passed to buildEncryptConfig — each table must have a unique name`,
      )
    }
    config.tables[tableDef.tableName] = tableDef.columns
  }

  return config
}

/** Map a domain's {@link PlaintextKind} to its TypeScript plaintext type. */
type PlaintextFromKind<K extends PlaintextKind> = K extends 'string'
  ? string
  : K extends 'number'
    ? number
    : K extends 'boolean'
      ? boolean
      : K extends 'date'
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
 * The concrete EQL v3 type string for a single column, read from the literal
 * domain definition carried on the base class's private field (mirrors
 * {@link PlaintextForColumn}). Distributes over a union of columns, so
 * `EqlTypeForColumn<AnyEncryptedV3Column>` yields the union of every domain's
 * `eqlType` — the canonical, source-of-truth key set for a type-driven test
 * matrix keyed by domain.
 */
export type EqlTypeForColumn<C> =
  C extends EncryptedV3Column<infer D> ? D['eqlType'] : never

/**
 * Infer the plaintext (decrypted) shape from a v3 table schema. Each column maps
 * to the TypeScript type of its domain's `castAs` kind.
 */
export type InferPlaintext<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C>
    ? { [K in keyof C]: PlaintextForColumn<C[K]> }
    : never

/**
 * Infer the encrypted shape from a v3 table schema. See {@link InferPlaintext}
 * for why no key-remap filter is needed in the flat single-type model.
 */
export type InferEncrypted<T extends EncryptedTable<EncryptedV3TableColumn>> =
  T extends EncryptedTable<infer C> ? { [K in keyof C]: Encrypted } : never

// ---------------------------------------------------------------------------
// Typed-client surface helpers (@cipherstash/stack/v3)
// ---------------------------------------------------------------------------

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

/** Any v3 table, regardless of its column map. */
export type AnyV3Table = EncryptedTable<EncryptedV3TableColumn>

/** Union of the concrete column builders declared on a v3 table. */
export type ColumnsOf<T extends AnyV3Table> =
  T extends EncryptedTable<infer C> ? C[keyof C] : never

/**
 * Union of the *queryable* column builders on a v3 table. Storage-only columns
 * (whose {@link QueryTypesForColumn} is `never`) are filtered out, so they can't
 * be passed to a query method.
 */
export type QueryableColumnsOf<T extends AnyV3Table> =
  T extends EncryptedTable<infer C>
    ? {
        [K in keyof C]: [QueryTypesForColumn<C[K]>] extends [never]
          ? never
          : C[K]
      }[keyof C]
    : never

/**
 * The accepted input model for {@link import('@/encryption/v3').TypedEncryptionClient.encryptModel}.
 * `T` is inferred from the argument: keys that name a schema column are pinned to
 * the column's plaintext type (nullable if the field is nullable), so a wrong-typed
 * field fails assignability; all other keys pass through unchanged.
 */
export type V3ModelInput<Table extends AnyV3Table, T> = {
  [K in keyof T]: K extends keyof InferPlaintext<Table>
    ? null extends T[K]
      ? InferPlaintext<Table>[K] | null
      : InferPlaintext<Table>[K]
    : T[K]
}

/** The encrypted result model: schema columns become `Encrypted`, others pass through. */
export type V3EncryptedModel<Table extends AnyV3Table, T> = {
  [K in keyof T]: K extends keyof InferPlaintext<Table>
    ? null extends T[K]
      ? Encrypted | null
      : Encrypted
    : T[K]
}

/** The decrypted result model: schema columns become their plaintext type, others pass through. */
export type V3DecryptedModel<Table extends AnyV3Table, T> = {
  [K in keyof T]: K extends keyof InferPlaintext<Table>
    ? null extends T[K]
      ? InferPlaintext<Table>[K] | null
      : InferPlaintext<Table>[K]
    : T[K]
}
