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
 * No call throws, and no promise rejects. Every call resolves to a `Result`.
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
export { Err, err, Ok, ok, type Result } from './result'
