// test-kit is an internal, source-only package that consumes stack through the
// `@/` alias (like `catalog.ts` does) — not through the published adapter seam.
// So we import `matchNeedleError` straight from `@/schema/match-defaults` rather
// than `@cipherstash/stack/adapter-kit`: the adapter-kit BARREL also re-exports
// `bulkModelsToEncryptedPgComposites` from `encryption/helpers`, and importing
// anything from that barrel drags the whole encryption/helpers → jsonb chain into
// test-kit's strict `tsc` graph (whose stricter options flag pre-existing loose
// types there). The published adapter packages, which have no `@/` alias, use the
// adapter-kit seam as intended; test-kit does not need it.
import { matchNeedleError } from '@/schema/match-defaults'
import type { V3_MATRIX } from './catalog'

type MatrixSpec = (typeof V3_MATRIX)[keyof typeof V3_MATRIX]

/**
 * Pick a sample from a match domain that can actually be used as a `matches`
 * needle. `sampleFor` is no good here — `TEXT_S[0]` is the empty string, which
 * tokenizes to nothing and is rejected as unanswerable.
 *
 * Selection runs the production predicate rather than a length check of our
 * own. A `sample.length >= 3` check would count UTF-16 code units where the
 * guard counts codepoints, so an astral sample ('👍👍': 4 units, 2 codepoints)
 * would be picked here and then thrown out by the guard, blaming the wrong
 * line. It would also ignore a domain that raises its own `token_length`.
 */
export const needleFor = (spec: MatrixSpec): string => {
  const match = 'match' in spec.indexes ? (spec.indexes.match ?? {}) : {}
  const needle = spec.samples.find(
    (sample) => typeof sample === 'string' && !matchNeedleError(sample, match),
  )
  if (typeof needle !== 'string') {
    throw new Error('no searchable sample for a match domain')
  }
  return needle
}
