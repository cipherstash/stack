/**
 * A cipher for tests: no credentials, no network.
 *
 * ```ts
 * import { testCipher } from '@cipherstash/recipher/testing'
 *
 * const cipher = (await testCipher()).unwrap()
 * ```
 *
 * Every key is a function of a seed and the value's context, so a value
 * sealed by one test cipher opens in another with the same seed, in the same
 * process or a later one. The keys are no secret from anyone who knows the
 * seed: never use a test cipher for data you keep.
 */
import { type Cipher, classes } from './cipher'
import type { RecipherError } from './error'
import type { Result } from './result'

/** The byte the seed of a test cipher is filled with when none is given. */
const DEFAULT_SEED_BYTE = 0x2a

/** Options for `testCipher`. */
export interface TestCipherOptions {
  /** 32 bytes that every key is derived from. */
  seed?: Uint8Array
}

/**
 * A cipher over the engine's deterministic test keys. Resolves to an `Err`
 * with the code `recipher::testing_seed` for a seed that is not 32 bytes,
 * or one whose getter throws, and `recipher::no_testing` when the native
 * build has no test cipher: only the debug build (`build:debug`) has one.
 */
export async function testCipher(
  options?: TestCipherOptions | null,
): Promise<Result<Cipher, RecipherError>> {
  let seed: unknown
  try {
    seed = options?.seed ?? new Uint8Array(32).fill(DEFAULT_SEED_BYTE)
  } catch {
    // Not a seed, so the native build refuses it as one.
    seed = undefined
  }
  return classes.createTesting(seed)
}
