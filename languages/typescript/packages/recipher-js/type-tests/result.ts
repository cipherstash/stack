// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. Each `@ts-expect-error` is a line that must not compile.
import {
  type Ciphertext,
  type Keyset,
  Ok,
  RecipherError,
  type Result,
} from '../src/index'

// `instanceof` narrows as `isOk()` does, and works on an unknown value.
declare const opened: Result<string, RecipherError>
if (opened instanceof Ok) {
  const text: string = opened.value
  void text
} else {
  const error: RecipherError = opened.error
  void error
}
declare const anything: unknown
if (anything instanceof RecipherError) {
  const code: string = anything.code
  void code
}

declare const sealed: Result<Ciphertext<string>, RecipherError>

// `isOk()` narrows: the value is readable only on the `Ok` side.
if (sealed.isOk()) {
  const value: Ciphertext<string> = sealed.value
  void value
} else {
  const error: RecipherError = sealed.error
  void error
  // @ts-expect-error: an `Err` has no value.
  void sealed.value
}

// `isErr()` narrows the other way, so an early return leaves an `Ok`.
function early(): Result<Ciphertext<string>, RecipherError> | Uint8Array {
  if (sealed.isErr()) {
    return sealed
  }
  return sealed.value.toBytes()
}
void early

// `unwrapOr` widens to the fallback's type.
const bytes: Uint8Array | null = sealed
  .map((ciphertext) => ciphertext.toBytes())
  .unwrapOr(null)
void bytes

// An error is its diagnostic: a caller switches on its code, a string.
function describe(error: RecipherError): string {
  const code: string = error.code
  // @ts-expect-error: an error has no kind; its code says what it is.
  void error.kind
  return code
}
void describe

declare const keyset: Keyset
// @ts-expect-error: this build encrypts a string only.
void keyset.encrypt(42n)
// @ts-expect-error: a plain object is not a value.
void keyset.encrypt({ name: 'Ada' })
