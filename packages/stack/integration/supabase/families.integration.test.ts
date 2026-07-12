import { FAMILY_NAMES } from '@cipherstash/test-kit'
import { runFamilySuite } from '@cipherstash/test-kit/suite'
import { makeSupabaseAdapter } from './adapter'

/**
 * Every EQL v3 domain the SDK models, driven through the Supabase adapter
 * against real ZeroKMS ciphertext.
 *
 * One file, not one per family. The driver derives the whole suite from the
 * catalog, so a per-family file was three identical lines and bought nothing:
 * `fileParallelism` is off (one database, shared tables), and vitest names each
 * failure by its `describe` path — `v3 supabase — text > text_match > …` — so a
 * failing family is just as identifiable from here.
 *
 * Iterating `FAMILY_NAMES` also closes a gap a hand-written file list cannot: a
 * new family added to the kit is covered without touching this file, and a
 * family removed from the kit cannot leave an orphaned suite behind.
 */
for (const family of FAMILY_NAMES) {
  runFamilySuite(family, makeSupabaseAdapter)
}
