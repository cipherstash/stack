/**
 * `RecipherError`: every failure, as a value.
 *
 * The native build defines the error's fields and its kinds
 * (`RecipherErrorFields` and `ErrorKind`, in the generated `native.d.ts`).
 * This class exists in TypeScript because an error has to exist when the
 * native build did not load.
 */
import type { ErrorCause, ErrorKind, RecipherErrorFields } from '../native'

export type { ErrorCause, ErrorKind, RecipherErrorFields }

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
 * - `message` says what went wrong, in one line.
 * - `help` says what to do about it, and `url` is a documentation page for
 *   the error, where the error has them.
 * - `fields` holds the error's structured fields by `snake_case` name, and
 *   is empty where it has none. `reason` and `field` are two of them, typed.
 * - `record` names the record a declaration, a row or a stored row is of.
 * - `causes` lists the errors behind this one, outermost first. A cause
 *   from another library has no code and a fixed message.
 *
 * No property, and no text it gives, holds a plaintext, a key, a token or a
 * ciphertext.
 */
export class RecipherError {
  readonly kind: ErrorKind
  readonly code: string
  readonly message: string
  readonly help: string | undefined
  readonly url: string | undefined
  readonly fields: Readonly<Record<string, unknown>>
  readonly causes: readonly ErrorCause[]
  readonly reason: string | undefined
  readonly field: string | undefined
  readonly record: string | undefined

  constructor(
    fields: Pick<RecipherErrorFields, 'kind' | 'code' | 'message'> &
      Partial<RecipherErrorFields>,
  ) {
    this.kind = fields.kind
    this.code = fields.code
    this.message = fields.message
    this.help = fields.help
    this.url = fields.url
    this.fields = Object.freeze({ ...fields.fields })
    this.causes = Object.freeze(
      (fields.causes ?? []).map((cause) => Object.freeze({ ...cause })),
    )
    this.reason = fields.reason
    this.field = fields.field
    this.record = fields.record
    Object.freeze(this)
  }

  /** The kind, code and message, then the help where there is one. */
  toString(): string {
    const text = `RecipherError(${this.kind}, ${this.code}): ${this.message}`
    return this.help === undefined ? text : `${text}\nhelp: ${this.help}`
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
  const {
    kind,
    code,
    message,
    help,
    url,
    fields,
    causes,
    reason,
    field,
    record,
  } = error as Record<string, unknown>
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
    ...(typeof help === 'string' ? { help } : {}),
    ...(typeof url === 'string' ? { url } : {}),
    ...(typeof fields === 'object' && fields !== null
      ? { fields: fields as Record<string, unknown> }
      : {}),
    causes: Array.isArray(causes) ? causes.flatMap(causeOf) : [],
    ...(typeof reason === 'string' ? { reason } : {}),
    ...(typeof field === 'string' ? { field } : {}),
    ...(typeof record === 'string' ? { record } : {}),
  })
}

/** A cause of the shape the native build writes, or nothing. */
function causeOf(cause: unknown): ErrorCause[] {
  if (typeof cause !== 'object' || cause === null) {
    return []
  }
  const { code, message } = cause as Record<string, unknown>
  if (typeof message !== 'string') {
    return []
  }
  return [typeof code === 'string' ? { code, message } : { message }]
}

/** An `internal` error of the SDK's own. */
export function internal(code: string, message: string): RecipherError {
  return new RecipherError({ kind: 'internal', code, message })
}
