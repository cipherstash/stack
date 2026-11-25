/**
 * Records: declarations of a row's fields. Each field is encrypted,
 * encrypted with indexes, or passed through unencrypted.
 *
 * ```ts
 * import { encrypt, kinds, passthrough, record } from '@cipherstash/recipher'
 *
 * export const user = record('users', {
 *   id: passthrough<bigint>(),
 *   email: encrypt(kinds.string, { index: ['equality'] }),
 *   name: encrypt(kinds.string, { index: ['match'] }),
 *   age: encrypt(kinds.int32, { index: ['equality'], null: 'sealed' }),
 *   notes: encrypt(kinds.string, { null: 'sql' }),
 * })
 * ```
 *
 * A declaration is a plain, frozen object: `{ type: 'record', name, fields }`,
 * with a declaration for each field. The native addon reads the declaration
 * and builds the engine's plan from it, once. The engine checks the
 * declaration at that time. That happens when a cipher first uses the
 * declaration, or when `Cipher.create({ records })` or
 * `checkDeclarations(..)` is called.
 *
 * TypeScript checks a row against the types below.
 *
 * The types are in `record-types.ts`, which never loads the addon, because
 * the addon's generated declarations (`native.d.ts`) import them.
 */
import { type Binding, binding } from './binding'
import type { RecipherError } from './error'
import type { Kind } from './kinds'
import type {
  Field,
  Index,
  NullMode,
  PassthroughField,
  RecordDeclaration,
  SealedField,
  SealedOptions,
} from './record-types'
import { err, type Result } from './result'

export type {
  CipherOptions,
  Field,
  Index,
  NullMode,
  PassthroughField,
  Plaintext,
  RecordDeclaration,
  SealedField,
  SealedFieldName,
  SealedOptions,
  Stored,
  StoredField,
} from './record-types'

/** An encrypted field of the kind `kind`. */
export function encrypt<
  K extends Kind,
  const I extends readonly Index[] = readonly [],
  N extends NullMode | undefined = undefined,
>(
  kind: K,
  options: SealedOptions<I, N> = {},
  // `NoInfer`: TypeScript reads what a field declares from `options` only.
  // TypeScript never takes it from the type that the caller's code expects.
  // That type names every index and every null mode.
): SealedField<K, NoInfer<I>, NoInfer<N>> {
  const index = Object.freeze([...(options.index ?? [])])
  const field =
    options.null === undefined
      ? { type: 'sealed', kind, index }
      : { type: 'sealed', kind, index, null: options.null }
  // biome-ignore lint/plugin: an empty array is the default `I`, `readonly []`.
  return Object.freeze(field) as unknown as SealedField<K, I, N>
}

/** A field passed through as it is. See `PassthroughField`. */
export function passthrough<T>(): PassthroughField<T> {
  return Object.freeze({ type: 'passthrough' })
}

/**
 * A record named `name`, with `fields`. Each field's context is its field
 * path: the record's name, then the field's name. A context is data that a
 * ciphertext is bound to. The ciphertext decrypts only under the same
 * context.
 */
export function record<
  const Name extends string,
  const F extends { readonly [field: string]: Field },
>(name: Name, fields: F): RecordDeclaration<Name, F> {
  return Object.freeze({
    type: 'record',
    name,
    fields: Object.freeze({ ...fields }),
  })
}

/**
 * Check declarations with the engine, with no credentials and no network
 * request. Use it in a test or a continuous integration (CI) step.
 *
 * The `Err` is the first refusal. The error names the record and, where
 * there is one, the field. When the native addon did not load, the `Err`
 * says why.
 */
export const checkDeclarations: Binding['checkDeclarations'] =
  checkDeclarationsOf(binding)

/**
 * The addon's `checkDeclarations` when the addon loaded, or a stand-in that
 * returns the load error when it did not.
 */
export function checkDeclarationsOf(
  loaded: Result<Binding, RecipherError>,
): Binding['checkDeclarations'] {
  if (loaded.isOk()) {
    return loaded.value.checkDeclarations
  }
  const error = loaded.error
  return () => err(error)
}
