/**
 * v3 codec ids, traits, and migration invariants. Parallel to the v2
 * `constants.ts`; imports NO v2 codec/wire code. Codec ids are the generated
 * closed union derived from the imported catalog: `(codec id) ⟺ (public.*
 * domain)` is bijective, so the id set IS the catalog.
 */
import type {
  AnyEncryptedV3Column,
  QueryCapabilities,
} from '@cipherstash/stack/eql/v3'
import {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
} from './constants'

export {
  CIPHERSTASH_TRAIT_EQUALITY,
  CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH,
  CIPHERSTASH_TRAIT_ORDER_AND_RANGE,
  CIPHERSTASH_TRAIT_SEARCHABLE_JSON,
}

/** Strip the `public.` schema qualifier at the type level. */
type StripSchema<T> = T extends `public.${infer D}` ? D : never

/**
 * Per-column literal `eqlType`, inferred from the `getEqlType()` return type
 * rather than the stack's `EqlTypeForColumn<C>`. NOT a style choice: the
 * stack's bundled `.d.ts` emits the base class's private `definition` field
 * without its type, so `C extends EncryptedV3Column<infer D>` (which
 * `EqlTypeForColumn` uses) has nothing to infer `D` from and falls back to the
 * constraint — widening every id to `` `public.${string}` `` and silently
 * disabling the closed-union drift guards below. The getter's declared return
 * type survives d.ts bundling because each concrete subclass binds `D`
 * explicitly in its `extends` clause.
 */
type EqlTypeFromGetter<C> = C extends { getEqlType(): infer T } ? T : never

/** Compile-time closed union: one concrete codec id per catalog domain. A
 * catalog change that adds/drops a domain surfaces as a type error at the
 * `satisfies` line below. The domain segment is the GA registry key VERBATIM
 * (`eql_v3_*`); the leading `eql-v3` path token is the logical version tag. */
export type CipherstashV3CodecId =
  `cipherstash/eql-v3/${StripSchema<EqlTypeFromGetter<AnyEncryptedV3Column>>}@1`

/**
 * PINNED literal tuple — the compile-time source of truth for the v3 codec-id
 * set. Hand-listed, one entry per catalog domain (INCLUDING the `*_ord_ore`
 * variants that authoring does not expose but the codec/derivation layer still
 * decodes). This is deliberately NOT `V3_CODEC_IDS as readonly CipherstashV3CodecId[]`
 * — that is a masking cast that asserts the derived array IS the union and so
 * catches NO drift. Here, catalog drift fails to COMPILE in both directions:
 *   - `satisfies readonly CipherstashV3CodecId[]` fails if a listed id is no
 *     longer a catalog domain (a domain removed / renamed).
 *   - `_NoUnpinnedDomain` (below) fails if the catalog gained a domain not
 *     pinned here.
 * The runtime drift test additionally asserts this equals the registry-derived
 * `V3_CODEC_IDS` (guarding the derivation itself).
 */
export const CIPHERSTASH_V3_CODEC_IDS = [
  'cipherstash/eql-v3/eql_v3_integer@1',
  'cipherstash/eql-v3/eql_v3_integer_eq@1',
  'cipherstash/eql-v3/eql_v3_integer_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_integer_ord@1',
  'cipherstash/eql-v3/eql_v3_smallint@1',
  'cipherstash/eql-v3/eql_v3_smallint_eq@1',
  'cipherstash/eql-v3/eql_v3_smallint_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_smallint_ord@1',
  'cipherstash/eql-v3/eql_v3_bigint@1',
  'cipherstash/eql-v3/eql_v3_bigint_eq@1',
  'cipherstash/eql-v3/eql_v3_bigint_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_bigint_ord@1',
  'cipherstash/eql-v3/eql_v3_date@1',
  'cipherstash/eql-v3/eql_v3_date_eq@1',
  'cipherstash/eql-v3/eql_v3_date_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_date_ord@1',
  'cipherstash/eql-v3/eql_v3_timestamp@1',
  'cipherstash/eql-v3/eql_v3_timestamp_eq@1',
  'cipherstash/eql-v3/eql_v3_timestamp_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_timestamp_ord@1',
  'cipherstash/eql-v3/eql_v3_numeric@1',
  'cipherstash/eql-v3/eql_v3_numeric_eq@1',
  'cipherstash/eql-v3/eql_v3_numeric_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_numeric_ord@1',
  'cipherstash/eql-v3/eql_v3_text@1',
  'cipherstash/eql-v3/eql_v3_text_eq@1',
  'cipherstash/eql-v3/eql_v3_text_match@1',
  'cipherstash/eql-v3/eql_v3_text_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_text_ord@1',
  'cipherstash/eql-v3/eql_v3_text_search@1',
  'cipherstash/eql-v3/eql_v3_boolean@1',
  'cipherstash/eql-v3/eql_v3_real@1',
  'cipherstash/eql-v3/eql_v3_real_eq@1',
  'cipherstash/eql-v3/eql_v3_real_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_real_ord@1',
  'cipherstash/eql-v3/eql_v3_double@1',
  'cipherstash/eql-v3/eql_v3_double_eq@1',
  'cipherstash/eql-v3/eql_v3_double_ord_ore@1',
  'cipherstash/eql-v3/eql_v3_double_ord@1',
  'cipherstash/eql-v3/eql_v3_json@1',
] as const satisfies readonly CipherstashV3CodecId[]

// Bidirectional drift guard — the direction `satisfies` cannot catch. If the
// catalog gains a domain that is not pinned above, `Exclude<...>` is non-`never`
// and this assignment fails to compile with the offending id in the error.
type _PinnedId = (typeof CIPHERSTASH_V3_CODEC_IDS)[number]
type _NoUnpinnedDomain = [Exclude<CipherstashV3CodecId, _PinnedId>] extends [
  never,
]
  ? true
  : [
      'catalog gained an unpinned codec id',
      Exclude<CipherstashV3CodecId, _PinnedId>,
    ]
const _driftGuard: _NoUnpinnedDomain = true
void _driftGuard

export const CIPHERSTASH_V3_CODEC_ID_SET: ReadonlySet<string> = new Set(
  CIPHERSTASH_V3_CODEC_IDS,
)

export function isCipherstashV3CodecId(id: string): id is CipherstashV3CodecId {
  return CIPHERSTASH_V3_CODEC_ID_SET.has(id)
}

export function v3TraitsForCapabilities(
  caps: QueryCapabilities,
): readonly string[] {
  const traits: string[] = []
  if (caps.equality) traits.push(CIPHERSTASH_TRAIT_EQUALITY)
  if (caps.orderAndRange) traits.push(CIPHERSTASH_TRAIT_ORDER_AND_RANGE)
  if (caps.freeTextSearch) traits.push(CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH)
  if (caps.searchableJson) traits.push(CIPHERSTASH_TRAIT_SEARCHABLE_JSON)
  return traits
}

export const CIPHERSTASH_V3_BASELINE_MIGRATION_NAME =
  '20260601T0100_install_eql_v3_bundle'

export const CIPHERSTASH_V3_INVARIANTS = {
  installBundle: 'cipherstash:install-eql-v3-bundle-v1',
} as const

// v3's OWN extension identity (decision 1b) — DISTINCT from the v2
// CIPHERSTASH_SPACE_ID / CIPHERSTASH_EXTENSION_VERSION. v2 and v3 are separate
// entry points, never co-registered in one client; the distinct id keeps the
// two extension descriptors cleanly separate. The shape mirrors the v2 id
// (a bare, path-safe token — it may be used as a directory segment) rather
// than a slashed namespace.
export const CIPHERSTASH_V3_SPACE_ID = 'cipherstash-eql-v3' as const
export const CIPHERSTASH_V3_EXTENSION_VERSION = '1.0.0' as const
