/**
 * Regression test: cipherstash v3 codec descriptors must NOT advertise
 * the framework's built-in `equality` trait.
 *
 * Re-adding a framework built-in trait to a cipherstash codec silently
 * re-introduces a wrong-SQL footgun: `COMPARISON_METHODS_META.eq` (in
 * `packages/3-extensions/sql-orm-client/src/types.ts`) gates the
 * framework's built-in `eq` on the column codec's `equality` trait, and
 * the built-in lowers to standard SQL `=`. EQL ciphertexts contain
 * randomized nonces, so two encrypts of the same plaintext do not
 * byte-equal under SQL `=` — a built-in `email.eq(...)` on an encrypted
 * column would produce `"email" = $1` and silently return zero matches.
 * The supported equality search is the cipherstash-namespaced `eqlEq`,
 * routed through the `cipherstash:v3-*` operator surface.
 *
 * Recorded here so a future change that flips a trait declaration
 * trips this test loudly rather than re-opening the footgun.
 */

import { describe, expect, it, vi } from 'vitest'
import type { CipherstashSdk } from '../src/execution/sdk'
import { createV3CodecDescriptors } from '../src/v3/codec-runtime-v3'

function emptySdk(): CipherstashSdk {
  return {
    decrypt: vi.fn(),
    bulkEncrypt: vi.fn(),
    bulkDecrypt: vi.fn(),
  }
}

describe('cipherstash v3 codec descriptors: no framework built-in traits', () => {
  it('every v3 descriptor advertises only cipherstash:* traits — never the framework built-in `equality`', () => {
    // A framework built-in trait on a v3 codec descriptor would
    // re-attach the built-in `eq` (SQL `=`) to encrypted columns, which
    // silently returns zero rows against nondeterministic ciphertexts.
    // Storage-only domains legitimately carry an EMPTY trait list (they
    // answer no operator at all), so the invariant is
    // subset-of-`cipherstash:*`, not non-empty.
    const descriptors = createV3CodecDescriptors(emptySdk())
    expect(descriptors.length).toBeGreaterThan(0)
    for (const descriptor of descriptors) {
      const traits: ReadonlyArray<string> = descriptor.traits ?? []
      for (const trait of traits) {
        expect(String(trait).startsWith('cipherstash:')).toBe(true)
      }
      expect(traits).not.toContain('equality')
    }
  })
})
