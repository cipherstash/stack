/**
 * Static names and identifiers used across CipherStash's contract space.
 *
 * The package installs EQL **v3** only; the v3-specific ids live in
 * `./constants-v3`. This module holds the identifiers shared by both the
 * control plane (pack meta / descriptor) and the v3 surface: the space id,
 * the extension version, and the `cipherstash:*` trait vocabulary.
 *
 * The space identifier `'cipherstash'` is what the framework writes to the
 * consuming app's `migrations/cipherstash/` directory and what the marker
 * table's `space` column carries for CipherStash-owned rows.
 */

export const CIPHERSTASH_SPACE_ID = 'cipherstash'

/**
 * Version advertised by both `cipherstashPackMeta.version` (control plane)
 * and the SDK-bound `SqlRuntimeExtensionDescriptor` (runtime plane).
 *
 * Single source of truth so the descriptor surfaces and the contract-emit
 * pack metadata cannot drift apart; consumed downstream by capability
 * gating and contract round-trips.
 */
export const CIPHERSTASH_EXTENSION_VERSION = '0.0.1' as const

/**
 * Cipherstash-namespaced codec traits. The v3 codec descriptors
 * (`../v3/codec-runtime-v3.ts`, `./codec-metadata.ts`) derive their trait
 * sets from these via `../extension-metadata/constants-v3.ts`
 * (`v3TraitsForCapabilities`), which re-exports them; the `eql*` query
 * operators register against the matching `cipherstash:v3-*` markers.
 *
 * The `cipherstash:` prefix is load-bearing — it isolates these traits from
 * the framework's built-in trait surface (`'equality'`, `'orderable'`,
 * `'numeric'`, `'boolean'`, …) so adding them to a cipherstash codec does
 * not silently re-enable a built-in operator (e.g. `equality` would
 * re-attach the framework's `eq` which lowers to standard SQL `=` — wrong
 * for EQL ciphers, see `equality-trait-removal.test.ts`). The cipherstash
 * extension owns its namespace; collisions with a future framework trait
 * are not possible.
 */
export const CIPHERSTASH_TRAIT_EQUALITY = 'cipherstash:equality' as const
export const CIPHERSTASH_TRAIT_ORDER_AND_RANGE =
  'cipherstash:order-and-range' as const
export const CIPHERSTASH_TRAIT_FREE_TEXT_SEARCH =
  'cipherstash:free-text-search' as const
export const CIPHERSTASH_TRAIT_SEARCHABLE_JSON =
  'cipherstash:searchable-json' as const
