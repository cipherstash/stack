/**
 * `RecipherError`: the error that a failed call returns, as a value.
 *
 * The native addon is the compiled Rust code that this package loads. The
 * addon defines the error's fields (`RecipherErrorFields`, in the generated
 * `native.d.ts`), and every error the addon reports. The addon makes each
 * error by calling this class's constructor with those fields. This class
 * is written in TypeScript because an error must still exist when the addon
 * did not load.
 */
import type { ErrorCause, RecipherErrorFields, Severity } from '../native'
import { hasBrand } from './result'

export type { ErrorCause, RecipherErrorFields, Severity }

/**
 * A failure, as a value. Every call that fails returns, or resolves to, an
 * `Err` that contains a `RecipherError`.
 *
 * - `code` is the code to switch on. A code is stable. A code is one of
 *   these:
 *   - the engine's error code, such as `stack_encrypt::aead`. The engine is
 *     Stack Encrypt, CipherStash's encryption engine;
 *   - the value bridge's code for a scalar it refused, such as
 *     `ERR_INTEGER_RANGE`. The value bridge is the part of the addon that
 *     converts JavaScript values;
 *   - the SDK's own code, such as `recipher_js::not_a_ciphertext`.
 * - `message` says what went wrong, in one line.
 * - `help` says what to do about the failure, when the error has that
 *   advice.
 * - `url` is a documentation page for the error, where it has one.
 * - `severity` is `error`, unless the engine's error report states `warning`
 *   or `advice`.
 * - `fields` contains the error's structured fields, by `snake_case` name.
 *   Examples are a refused declaration's `reason` and a ZeroKMS failure's
 *   `request_kind`. `fields` is empty when the error has no structured
 *   fields.
 * - `field` names the field at fault, where one is known.
 * - `record` names the record that the failed declaration, row, or stored
 *   row belongs to.
 * - `causes` lists the errors behind this one, outermost first. A cause from
 *   another library has no code, and a fixed message.
 *
 * No property, and no text that the error gives, contains a plaintext, a
 * key, a token, or a ciphertext.
 */
export class RecipherError {
  /**
   * Whether `value` is a `RecipherError`, from either build of this
   * package. The ESM and the CommonJS builds each have their own class, and
   * the addon makes every error with the class of the build that loaded
   * first. Both classes check the same brand.
   */
  static [Symbol.hasInstance](value: unknown): value is RecipherError {
    return hasBrand(value, ERROR_BRAND)
  }

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

/** The brand that `instanceof RecipherError` checks. */
const ERROR_BRAND = Symbol.for('@cipherstash/recipher.RecipherError')
Object.defineProperty(RecipherError.prototype, ERROR_BRAND, { value: true })

/**
 * An error that the TypeScript makes itself. The TypeScript makes one when
 * the addon did not load, or is not one this TypeScript can call.
 * The addon makes every other error.
 */
export function sdkError(code: string, message: string): RecipherError {
  return new RecipherError({ code, message })
}
