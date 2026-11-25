// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. The package's types are the ones napi-rs generates from the Rust
// in `native.d.ts`. These check that the exported types are those, and
// that the signatures written in Rust's `ts_type` attributes say what the
// API promises. Each `@ts-expect-error` is a line that must not compile.
import type * as Native from '../native'
import {
  Cipher,
  Ciphertext,
  type CiphertextClass,
  Keyset,
  type RecipherError,
  type Result,
} from '../src/index'

function check<_ extends true>(): void {}

type Equal<A, B> =
  (<X>() => X extends A ? 1 : 2) extends <X>() => X extends B ? 1 : 2
    ? true
    : false

// The exported instance types are the generated ones.
check<Equal<Cipher, Native.Cipher>>()
check<Equal<Keyset, Native.Keyset>>()
check<Equal<Ciphertext<number>, Native.Ciphertext<number>>>()
// A ciphertext with no type named decrypts to a string, as this build
// encrypts strings only.
check<Equal<Ciphertext, Ciphertext<string>>>()

// The static methods are the generated ones.
check<Equal<CiphertextClass['fromBytes'], typeof Native.Ciphertext.fromBytes>>()
check<
  Equal<
    ReturnType<typeof Cipher.create>,
    Promise<Result<Cipher, RecipherError>>
  >
>()

// A ciphertext's type parameter is kept: one that decrypts to a number is
// not one that decrypts to a string.
declare const number: Ciphertext<number>
// @ts-expect-error: a `Ciphertext<number>` is not a `Ciphertext<string>`.
const text: Ciphertext<string> = number
void text

// Decrypting gives the ciphertext's type, from a cipher or a keyset.
declare const cipher: Cipher
declare const keyset: Keyset
async function decrypts(): Promise<void> {
  const opened: Result<number, RecipherError> = await cipher.decrypt(number)
  const fromKeyset: Result<number, RecipherError> = await keyset.decrypt(number)
  // @ts-expect-error: a `Ciphertext<number>` does not decrypt to a string.
  const wrong: Result<string, RecipherError> = await cipher.decrypt(number)
  void opened
  void fromKeyset
  void wrong
  const sealed = await keyset.encrypt('x')
  if (sealed.isOk()) {
    const value: Ciphertext<string> = sealed.value
    void value
  }
}
void decrypts

// The classes have no constructor: a cipher, a keyset and a ciphertext come
// from the calls that make them.
// @ts-expect-error: `Cipher` has no constructor.
void new Cipher()
// @ts-expect-error: `Keyset` has no constructor.
void new Keyset()
// @ts-expect-error: `Ciphertext` has no constructor.
void new Ciphertext()

// `instanceof` narrows to the class's instances.
declare const value: unknown
if (value instanceof Ciphertext) {
  const bytes: Uint8Array = value.toBytes()
  void bytes
}
