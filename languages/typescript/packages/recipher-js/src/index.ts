/**
 * `@cipherstash/recipher`: encrypt values with per-value ZeroKMS data keys,
 * through the Stack Encrypt engine.
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
 * No call throws and no promise rejects: every call resolves to a `Result`.
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
  type ErrorKind,
  RecipherError,
  type RecipherErrorFields,
} from './error'
export { Err, err, Ok, ok, type Result } from './result'
