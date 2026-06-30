import type { ColumnSchema, MatchIndexOpts } from '@/schema'

/**
 * The concrete EQL v3 domain name for a full-capability text column.
 * Recorded as metadata for future DDL / query-dialect increments; it is
 * intentionally absent from the emitted encrypt config.
 */
export const TEXT_SEARCH_EQL_TYPE = 'eql_v3.text_search'

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
 * Builder for an `eql_v3.text_search` column.
 *
 * The concrete type inherently enables equality + order/range + free-text
 * match — there are no capability-enabling methods. `.freeTextSearch(opts?)`
 * tunes the match index only.
 */
export class EncryptedTextSearchColumn {
  private readonly columnName: string
  private matchOpts: BuiltMatchIndexOpts

  constructor(columnName: string) {
    this.columnName = columnName
    this.matchOpts = defaultMatchOpts()
  }

  /**
   * The concrete EQL v3 domain name. Metadata only; not emitted by `build()`.
   * Method (not a property getter) to match the v2 builder convention.
   */
  getEqlType(): typeof TEXT_SEARCH_EQL_TYPE {
    return TEXT_SEARCH_EQL_TYPE
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
    this.matchOpts = {
      tokenizer: opts?.tokenizer ?? defaults.tokenizer,
      token_filters: opts?.token_filters ?? defaults.token_filters,
      k: opts?.k ?? defaults.k,
      m: opts?.m ?? defaults.m,
      include_original: opts?.include_original ?? defaults.include_original,
    }
    return this
  }

  /** Emit the encrypt-config column. Byte-identical to a v2 equality+order+match column. */
  build(): ColumnSchema {
    // `cast_as` is typed `CastAs` by the `ColumnSchema` return type, so the
    // literal is checked here without a redundant local annotation.
    //
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

  getName(): string {
    return this.columnName
  }
}

/**
 * Define an `eql_v3.text_search` column. The concrete type carries all three
 * capabilities (equality + order/range + free-text match). Chain
 * `.freeTextSearch(opts)` to tune the match index.
 */
export function encryptedTextSearchColumn(
  columnName: string,
): EncryptedTextSearchColumn {
  return new EncryptedTextSearchColumn(columnName)
}
