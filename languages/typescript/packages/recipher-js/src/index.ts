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
  type CipherOptions,
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
export {
  checkDeclarations,
  encrypt,
  type Field,
  type Index,
  type NullMode,
  type PassthroughField,
  type Plaintext,
  passthrough,
  type RecordDeclaration,
  record,
  type SealedField,
  type SealedFieldName,
  type SealedOptions,
  type Stored,
  type StoredField,
} from './record'
export { Err, err, Ok, ok, type Result } from './result'
export {
  type Json,
  type JsonFunction,
  type JsonValue,
  json,
  type Opened,
  type OpenedJson,
  type OpenedScalar,
  type Scalar,
  type Value,
  VcDate,
  VcDecimal,
  VcTimestamp,
  VcUuid,
  type WrapperConstructor,
} from './values'
