/**
 * A cipher for tests. A test cipher needs no credentials and makes no
 * network requests.
 *
 * ```ts
 * import { testCipher } from '@cipherstash/recipher/testing'
 *
 * const cipher = (await testCipher()).unwrap()
 * ```
 *
 * Every key is derived from a seed and the value's context. The context is
 * data that a ciphertext is bound to. A value encrypted by one test cipher
 * decrypts with another test cipher that has the same seed. That works in
 * the same process or in a later one.
 *
 * Anyone who knows the seed can derive the keys. Never use a test cipher for
 * data you keep.
 */
import { type Cipher, classes } from './cipher'
import type { RecipherError } from './error'
import type { Result } from './result'

/** The byte that fills a test cipher's seed when no seed is given. */
const DEFAULT_SEED_BYTE = 0x2a

/** Options for `testCipher`. */
export interface TestCipherOptions {
  /** 32 bytes that every key is derived from. */
  seed?: Uint8Array
}

/**
 * A cipher that uses the engine's deterministic test keys. The same seed
 * always gives the same keys.
 *
 * Resolves to an `Err` with the code `recipher_js::testing_seed` in these
 * cases: the seed is not 32 bytes, `options` is not an object, or reading
 * `options.seed` throws. Resolves to an
 * `Err` with the code `recipher_js::no_testing` when the native addon has no
 * test cipher. Only the debug build of the addon (`build:debug`) has one.
 */
export async function testCipher(
  options?: TestCipherOptions | null,
): Promise<Result<Cipher, RecipherError>> {
  let seed: unknown
  try {
    if (options === undefined || options === null) {
      seed = new Uint8Array(32).fill(DEFAULT_SEED_BYTE)
    } else if (typeof options !== 'object') {
      // A number, string or other primitive is not options. `undefined` is
      // not a seed, so the addon refuses it with `recipher_js::testing_seed`.
      seed = undefined
    } else {
      seed = options.seed ?? new Uint8Array(32).fill(DEFAULT_SEED_BYTE)
    }
  } catch {
    // `undefined` is not a seed, so the addon refuses it with
    // `recipher_js::testing_seed`.
    seed = undefined
  }
  return classes.createTesting(seed)
}
