/**
 * `RecipherError`: every failure, as a value.
 *
 * The native build defines the error's fields (`RecipherErrorFields`, in the
 * generated `native.d.ts`) and every error it reports. This class exists in
 * TypeScript because an error has to exist when the native build did not
 * load.
 */
import type { ErrorCause, RecipherErrorFields, Severity } from '../native'

export type { ErrorCause, RecipherErrorFields, Severity }

/**
 * A failure, as a value. Every call that fails resolves to an `Err` holding
 * one; none throws.
 *
 * - `code` is stable, and is what to switch on: the engine's diagnostic
 *   code, such as `stack_encrypt::aead`, vitaminc's code for a value it
 *   refused, such as `ERR_INTEGER_RANGE`, or the SDK's own, such as
 *   `recipher::not_a_ciphertext`.
 * - `message` says what went wrong, in one line.
 * - `help` says what to do about it, and `url` is a documentation page for
 *   the error, where the error has them.
 * - `severity` is `error`, unless the engine's diagnostic states `warning`
 *   or `advice`.
 * - `fields` holds the error's structured fields by `snake_case` name, and
 *   is empty where it has none: a refused declaration's `reason`, a
 *   ZeroKMS failure's `request_kind`.
 * - `field` names the field at fault, where one is known.
 * - `record` names the record a declaration, a row or a stored row is of.
 * - `causes` lists the errors behind this one, outermost first. A cause
 *   from another library has no code and a fixed message.
 *
 * No property, and no text it gives, holds a plaintext, a key, a token or a
 * ciphertext.
 */
export class RecipherError {
  readonly code: string
  readonly message: string
  readonly help: string | undefined
  readonly url: string | undefined
  readonly severity: Severity
  readonly fields: Readonly<Record<string, unknown>>
  readonly causes: readonly ErrorCause[]
  readonly field: string | undefined
  readonly record: string | undefined

  constructor(
    fields: Pick<RecipherErrorFields, 'code' | 'message'> &
      Partial<RecipherErrorFields>,
  ) {
    this.code = fields.code
    this.message = fields.message
    this.help = fields.help
    this.url = fields.url
    this.severity = fields.severity ?? 'error'
    this.fields = Object.freeze({ ...fields.fields })
    this.causes = Object.freeze(
      (fields.causes ?? []).map((cause) => Object.freeze({ ...cause })),
    )
    this.field = fields.field
    this.record = fields.record
    Object.freeze(this)
  }

  /** The code and message, then the help where there is one. */
  toString(): string {
    const text = `RecipherError(${this.code}): ${this.message}`
    return this.help === undefined ? text : `${text}\nhelp: ${this.help}`
  }
}

/**
 * The error of a native outcome. The native build writes it, so this only
 * checks that it has the shape.
 */
export function fromNative(error: unknown): RecipherError {
  const { code, message, help, url, severity, fields, causes, field, record } =
    typeof error === 'object' && error !== null
      ? (error as Record<string, unknown>)
      : {}
  if (typeof code !== 'string' || typeof message !== 'string') {
    return sdkError(
      'recipher::outcome',
      'the native build returned an error of an unknown shape',
    )
  }
  return new RecipherError({
    code,
    message,

    ...(typeof help === 'string' ? { help } : {}),
    ...(typeof url === 'string' ? { url } : {}),
    ...(severity === 'warning' || severity === 'advice' ? { severity } : {}),
    ...(typeof fields === 'object' && fields !== null
      ? { fields: fields as Record<string, unknown> }
      : {}),
    causes: Array.isArray(causes) ? causes.flatMap(causeOf) : [],
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

/**
 * An error the TypeScript raises itself, for a native build that did not
 * load or did not answer as it should. Every other error is the native
 * build's.
 */
export function sdkError(code: string, message: string): RecipherError {
  return new RecipherError({ code, message })
}
