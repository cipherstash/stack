// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. The typed signatures in `src/cipher.ts` are over the native
// classes napi-rs declares in `native.d.ts`; each method they name must be
// one the native class has, so a method renamed or removed in Rust fails
// here rather than at run time.
import type * as Native from '../native'
import type {
  Cipher,
  CipherClass,
  Ciphertext,
  CiphertextClass,
  Keyset,
} from '../src/index'

function check<_ extends true>(): void {}

/**
 * Whether every string key of `Typed` is a key of `Declared`. A symbol key
 * is the TypeScript's own (`instanceof`, and the type a ciphertext opens
 * as), which nothing at run time holds.
 */
type Covers<Declared, Typed> =
  Exclude<keyof Typed, keyof Declared | symbol> extends never ? true : false

check<Covers<Native.Cipher, Cipher>>()
check<Covers<Native.Keyset, Keyset>>()
check<Covers<Native.Ciphertext, Ciphertext>>()
check<Covers<typeof Native.Cipher, CipherClass>>()
check<Covers<typeof Native.Ciphertext, CiphertextClass>>()

// The check itself fails for a method the native class does not have.
interface Extra extends Cipher {
  encryptEverything(): void
}
// @ts-expect-error: `encryptEverything` is not a native method.
check<Covers<Native.Cipher, Extra>>()
