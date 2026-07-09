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

/**
 * Resolve user-supplied `freeTextSearch(opts)` input into a fully-built match
 * block: each provided key replaces its default, omitted keys keep the default
 * (`opts?.x ?? default.x`). The single source of truth for that five-field merge
 * shared by the v2 `freeTextSearch()` builder and the v3 domain builders.
 *
 * The result is deep-cloned ({@link cloneMatchOpts}) so a caller mutating their
 * own `opts` object (or its nested `tokenizer`/`token_filters`) after this call
 * can never leak into the stored builder state or the emitted config — clone-on-
 * write for both builders, not just v3.
 */
export function resolveMatchOpts(opts?: MatchIndexOpts): BuiltMatchIndexOpts {
  const defaults = defaultMatchOpts()
  return cloneMatchOpts({
    tokenizer: opts?.tokenizer ?? defaults.tokenizer,
    token_filters: opts?.token_filters ?? defaults.token_filters,
    k: opts?.k ?? defaults.k,
    m: opts?.m ?? defaults.m,
    include_original: opts?.include_original ?? defaults.include_original,
  })
}

/**
 * The shortest needle a match index can answer, or `undefined` when its
 * tokenizer imposes no floor (`standard` splits on word boundaries, so any
 * non-empty needle yields at least one token).
 *
 * Accepts the loose {@link MatchIndexOpts} because a `ColumnSchema`'s built
 * `indexes.match` is typed from the zod schema, where `tokenizer` is optional.
 * An absent tokenizer resolves to the same default the schema itself applies
 * (`ngram`, `token_length: 3`) rather than skipping the floor — skipping would
 * reintroduce the fail-open this guard exists to close.
 */
export function matchNeedleMinLength(opts: MatchIndexOpts): number | undefined {
  const tokenizer = opts.tokenizer ?? defaultMatchOpts().tokenizer
  return tokenizer.kind === 'ngram' ? tokenizer.token_length : undefined
}

/**
 * Why a needle cannot be answered by this match index, or `undefined` when it
 * can. Callers throw their own error type with this as the reason.
 *
 * A needle shorter than the ngram tokenizer's `token_length` produces NO
 * ngrams, so its bloom filter is empty — and `stored_bf @> '{}'` is true for
 * every row ("contains nothing, contained by everything"). Such a query is
 * unanswerable rather than merely unmatched, so it must fail loudly instead of
 * silently returning the whole table.
 *
 * Shared by the v2 and v3 adapters: both build byte-identical bloom filters, so
 * the floor is a property of the index config, not of the adapter version.
 */
export function matchNeedleError(
  needle: unknown,
  opts: MatchIndexOpts,
): string | undefined {
  if (typeof needle !== 'string') return undefined
  const min = matchNeedleMinLength(opts)
  if (min === undefined || needle.length >= min) return undefined
  return `free-text search needs at least ${min} characters (the index tokenizer's token_length), but the search term ${JSON.stringify(needle)} has ${needle.length}. A shorter term produces no tokens and would match every row.`
}
