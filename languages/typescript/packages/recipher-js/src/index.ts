/**
 * `@cipherstash/recipher` encrypts values through the Stack Encrypt engine,
 * CipherStash's encryption engine. Each value gets a data key of its own
 * from ZeroKMS, CipherStash's key service.
 *
 * ```ts
 * import { Cipher } from '@cipherstash/recipher'
 *
 * const cipher = (await Cipher.create()).unwrap()
 * const keyset = cipher.defaultKeyset()
 *
 * const sealed = await keyset.encrypt('a secret message')
 * if (sealed.isErr()) {
 *   return sealed
 * }
 * const opened = await cipher.decrypt(sealed.value)
 * ```
 *
 * Every call returns, or resolves to, a `Result`, and no promise rejects. A
 * call with an argument of the wrong type is an `Err`, not an exception.
 *
 * The one exception is a method called without its object, as in
 * `stored.map(cipher.decrypt)`. The JavaScript engine throws a `TypeError`
 * for it, before any of the package's code runs. Call each method on its
 * object: `stored.map((ciphertext) => cipher.decrypt(ciphertext))`.
 */
export {
  Cipher,
  type CipherClass,
  Ciphertext,
  type CiphertextClass,
  Keyset,
  type KeysetClass,
} from './cipher'
export {
  type ErrorCause,
  RecipherError,
  type RecipherErrorFields,
  type Severity,
} from './error'
export { type Kind, kinds, type ValueOf } from './kinds'
export { Err, err, Ok, ok, type Result } from './result'
export {
  type Json,
  type JsonFunction,
  type JsonValue,
  json,
  type Opened,
  type OpenedJson,
  type OpenedScalar,
  RcDate,
  RcDecimal,
  RcTimestamp,
  RcUuid,
  type Scalar,
  type Value,
  type WrapperConstructor,
} from './values'
