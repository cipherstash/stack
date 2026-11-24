/**
 * `RecipherError`: every failure, as a value.
 *
 * The native build defines the error's fields and its kinds
 * (`RecipherErrorFields` and `ErrorKind`, in the generated `native.d.ts`).
 * This class exists in TypeScript because an error has to exist when the
 * native build did not load.
 */
import type { ErrorKind, RecipherErrorFields } from '../native'

export type { ErrorKind, RecipherErrorFields }

const KINDS: ReadonlySet<string> = new Set<ErrorKind>([
  'declaration',
  'value',
  'credential',
  'zerokms',
  'foreign_keyset',
  'context_mismatch',
  'open',
  'cancelled',
  'internal',
])

/**
 * A failure, as a value. Every call that fails resolves to an `Err` holding
 * one; none throws.
 *
 * - `kind` is the closed set to switch on. A `switch` that leaves a kind
 *   out does not compile when its default case is checked as `never`.
 * - `code` is stable: the engine's diagnostic code, such as
 *   `stack_encrypt::aead`, vitaminc's code for a value it refused, such as
 *   `ERR_INTEGER_RANGE`, or the SDK's own, such as `recipher::load`.
 * - `message` says what went wrong.
 * - `reason` and `field` are the engine's, where it names them.
 *
 * No property, and no text it gives, holds a plaintext, a key, a token or a
 * ciphertext.
 */
export class RecipherError {
  readonly kind: ErrorKind
  readonly code: string
  readonly message: string
  readonly reason: string | undefined
  readonly field: string | undefined

  constructor(fields: RecipherErrorFields) {
    this.kind = fields.kind
    this.code = fields.code
    this.message = fields.message
    this.reason = fields.reason
    this.field = fields.field
    Object.freeze(this)
  }

  toString(): string {
    return `RecipherError(${this.kind}, ${this.code}): ${this.message}`
  }
}

/**
 * The error of a native outcome. The native build writes it, so this only
 * checks that it has the shape and a known kind.
 */
export function fromNative(error: unknown): RecipherError {
  if (typeof error !== 'object' || error === null) {
    return internal(
      'recipher::outcome',
      'the native build returned an error of an unknown shape',
    )
  }
  const { kind, code, message, reason, field } = error as Record<
    string,
    unknown
  >
  if (typeof kind !== 'string' || !KINDS.has(kind)) {
    return internal(
      'recipher::outcome',
      'the native build returned an error of an unknown kind',
    )
  }
  return new RecipherError({
    kind: kind as ErrorKind,
    code: typeof code === 'string' ? code : 'recipher::unknown',
    message: typeof message === 'string' ? message : '',
    ...(typeof reason === 'string' ? { reason } : {}),
    ...(typeof field === 'string' ? { field } : {}),
  })
}

/** An `internal` error of the SDK's own. */
export function internal(code: string, message: string): RecipherError {
  return new RecipherError({ kind: 'internal', code, message })
}
