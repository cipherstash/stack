import type { MatchIndexOpts } from './index'

/**
 * Fully-resolved match-index options: every field present and non-`undefined`.
 *
 * `MatchIndexOpts` (the user-facing tuning input) has all fields optional —
 * each is `.default(...).optional()` in the zod schema, so its inferred type is
 * `T | undefined`. This type pins the BUILT/resolved shape explicitly via
 * `NonNullable<...>`, which states the non-null intent directly and is robust
 * regardless of `Required<>`'s subtle, `exactOptionalPropertyTypes`-dependent
 * stripping semantics.
 */
export type BuiltMatchIndexOpts = {
  tokenizer: NonNullable<MatchIndexOpts['tokenizer']>
  token_filters: NonNullable<MatchIndexOpts['token_filters']>
  k: NonNullable<MatchIndexOpts['k']>
  m: NonNullable<MatchIndexOpts['m']>
  include_original: NonNullable<MatchIndexOpts['include_original']>
}

/**
 * Default match-index parameters — the single source of truth shared by the
 * v2 `freeTextSearch()` builder and the v3 domain builders (note
 * `include_original: true`, which is the v2 builder default rather than the
 * zod-schema default of `false`).
 *
 * This is a FACTORY (not a shared `const`) so every caller gets fresh, unaliased
 * nested objects (`tokenizer`, `token_filters` and the `{ kind: 'downcase' }`
 * inside it). A shared const would be shallow-copied by `{ ...DEFAULT }`, leaving
 * those nested objects aliased across every column — a caller mutating one built
 * config could then corrupt the defaults used by later columns.
 */
export function defaultMatchOpts(): BuiltMatchIndexOpts {
  return {
    tokenizer: { kind: 'ngram', token_length: 3 },
    token_filters: [{ kind: 'downcase' }],
    k: 6,
    m: 2048,
    include_original: true,
  }
}

/**
 * Deep-clone a built match block (`tokenizer` and `token_filters` are its only
 * nested values) so no emitted config or stored builder state ever aliases
 * another's nested objects — a caller mutating one cannot corrupt the other.
 */
export function cloneMatchOpts(opts: BuiltMatchIndexOpts): BuiltMatchIndexOpts {
  return {
    ...opts,
    tokenizer: { ...opts.tokenizer },
    token_filters: opts.token_filters.map((f) => ({ ...f })),
  }
}
