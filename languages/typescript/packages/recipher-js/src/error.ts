/**
 * `RecipherError`: the error that a failed call returns, as a value.
 *
 * The native addon is the compiled Rust code that this package loads. The
 * addon defines the error's fields (`RecipherErrorFields`, in the generated
 * `native.d.ts`), and every error the addon reports. This class is written
 * in TypeScript because an error must still exist when the addon did not
 * load.
 */
import type { ErrorCause, RecipherErrorFields, Severity } from '../native'

export type { ErrorCause, RecipherErrorFields, Severity }

/**
 * A failure, as a value. Every call that fails resolves to an `Err` that
 * contains a `RecipherError`. No call throws.
 *
 * - `code` is the code to switch on. It is stable. It is one of these:
 *   - the engine's error code, such as `stack_encrypt::aead`;
 *   - vitaminc's code for a value it refused, such as `ERR_INTEGER_RANGE`.
 *     vitaminc is the CipherStash Rust library that the engine's plaintext
 *     types come from;
 *   - the SDK's own code, such as `recipher::not_a_ciphertext`.
 * - `message` says what went wrong, in one line.
 * - `help` says what to do about it, where the error knows.
 * - `url` is a documentation page for the error, where it has one.
 * - `severity` is `error`, unless the engine's error report states
 *   `warning` or `advice`.
 * - `fields` contains the error's structured fields, by `snake_case` name.
 *   Examples are a refused declaration's `reason` and a ZeroKMS failure's
 *   `request_kind`. `fields` is empty when the error has no structured
 *   fields.
 * - `field` names the field at fault, where one is known.
 * - `record` names the record that the failed declaration, row, or stored
 *   row belongs to.
 * - `causes` lists the errors behind this one, outermost first. A cause
 *   from another library has no code, and a fixed message.
 *
 * No property, and no text that the error gives, contains a plaintext, a
 * key, a token, or a ciphertext.
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

  /** Text with the code and the message, then the help where there is one. */
  toString(): string {
    const text = `RecipherError(${this.code}): ${this.message}`
    return this.help === undefined ? text : `${text}\nhelp: ${this.help}`
  }
}

/**
 * Make a `RecipherError` from the error in a native outcome. A native
 * outcome is the object a native method returns: `{ ok, value }` or
 * `{ ok, error }`. The addon writes the error, so this function only checks
 * the error's shape.
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

/**
 * The cause, in a one-item array, when it has the shape that the addon
 * writes. Otherwise, an empty array.
 */
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
 * An error that the TypeScript makes itself. The TypeScript makes one when
 * the addon did not load, or when the addon did not return what it should.
 * The addon makes every other error.
 */
export function sdkError(code: string, message: string): RecipherError {
  return new RecipherError({ code, message })
}
