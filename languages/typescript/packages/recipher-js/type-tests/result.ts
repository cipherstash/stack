// Compile-time tests: `pnpm run typecheck` compiles this file and nothing
// runs it. Each `@ts-expect-error` is a line that must not compile.
import type {
  Ciphertext,
  ErrorKind,
  Keyset,
  RecipherError,
  Result,
} from '../src/index'

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

// A switch over the kinds covers every one, or the `never` does not compile.
function describe(kind: ErrorKind): string {
  switch (kind) {
    case 'declaration':
    case 'value':
    case 'credential':
    case 'zerokms':
    case 'foreign_keyset':
    case 'context_mismatch':
    case 'open':
    case 'cancelled':
    case 'internal':
      return kind
    default: {
      const unhandled: never = kind
      return unhandled
    }
  }
}
void describe

function missesOne(kind: ErrorKind): string {
  switch (kind) {
    case 'declaration':
    case 'value':
    case 'credential':
    case 'zerokms':
    case 'foreign_keyset':
    case 'context_mismatch':
    case 'open':
    case 'cancelled':
      return kind
    default: {
      // @ts-expect-error: `internal` is not handled.
      const unhandled: never = kind
      return unhandled
    }
  }
}
void missesOne

declare const keyset: Keyset
// @ts-expect-error: this build encrypts a string only.
void keyset.encrypt(42n)
// @ts-expect-error: a plain object is not a value.
void keyset.encrypt({ name: 'Ada' })
