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
 */
import { binding, settle } from './binding'
import type { RecipherError } from './error'
import type { Kind, ValueOf } from './kinds'
import { err, type Result } from './result'

/**
 * An index that an encrypted field stores beside its ciphertext. An index
 * stores index terms: bytes that a search can compare without decrypting the
 * field.
 */
export type Index = 'equality' | 'match' | 'ore' | 'ope'

/**
 * How a field stores a missing value.
 *
 * - `sealed`: the null is encrypted like a value, to the same length as a
 *   value. The stored row does not show which rows have no value. Only for
 *   a field of fixed width whose only index is `equality`. The fixed-width
 *   fields are a boolean, a number, a date, a timestamp, and a decimal.
 * - `sql`: the stored row has `null` for the field, as SQL `NULL` does.
 */
export type NullMode = 'sealed' | 'sql'

/**
 * A field that is encrypted, and indexed if it names indexes. The code calls
 * an encrypted field a sealed field.
 */
export interface SealedField<
  K extends Kind = Kind,
  I extends readonly Index[] = readonly Index[],
  N extends NullMode | undefined = NullMode | undefined,
> {
  readonly type: 'sealed'
  readonly kind: K
  readonly index: I
  readonly null?: N
}

/**
 * A field stored as it is: **not encrypted and not authenticated.** Anyone
 * with the stored row can read the field, change it, or remove it. The
 * encrypted fields still decrypt after that. Use a passthrough field only
 * for values that are not secret. Treat the value read back as untrusted.
 */
export interface PassthroughField<T = unknown> {
  readonly type: 'passthrough'
  /** Carries `T` for the type checker. The property never exists at run time. */
  readonly __value?: T
}

/** A field of a record. */
export type Field = SealedField | PassthroughField

/** Options for an encrypted field. */
export interface SealedOptions<
  I extends readonly Index[],
  N extends NullMode | undefined,
> {
  /** The indexes the field stores. */
  index?: I
  /**
   * How the field stores a null. Without this option, every row needs a
   * value for the field.
   */
  null?: N
}

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

/** A record's declaration: a plain, frozen object. */
export interface RecordDeclaration<
  Name extends string = string,
  F extends { readonly [field: string]: Field } = {
    readonly [field: string]: Field
  },
> {
  /**
   * Marks the object as a declaration. Every copy of the package reads this
   * marker, including the ESM build and the CommonJS build.
   */
  readonly type: 'record'
  /** The record's name: the first part of each field's context. */
  readonly name: Name
  /** The fields, each with its declaration. */
  readonly fields: F
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

/** The plaintext row of a record. A field that takes a null can be `null`. */
export type Plaintext<R> =
  R extends RecordDeclaration<string, infer F>
    ? {
        -readonly [P in keyof F]: F[P] extends SealedField<
          infer K,
          readonly Index[],
          infer N
        >
          ? ValueOf<K> | (N extends NullMode ? null : never)
          : F[P] extends PassthroughField<infer T>
            ? T
            : never
      }
    : never

/** An encrypted field as it is stored: its ciphertext and its index terms. */
export type StoredField<I extends readonly Index[] = readonly Index[]> = {
  readonly ciphertext: Uint8Array
} & { readonly [X in I[number]]: Uint8Array }

/**
 * The stored row of a record. Each encrypted field has its ciphertext and
 * its index terms, each as opaque bytes. Each passthrough field has its
 * value. A field that stores a null as SQL `NULL` is `null` when its value
 * is missing.
 */
export type Stored<R> =
  R extends RecordDeclaration<string, infer F>
    ? {
        readonly [P in keyof F]: F[P] extends SealedField<
          Kind,
          infer I,
          infer N
        >
          ? StoredField<I> | (N extends 'sql' ? null : never)
          : F[P] extends PassthroughField<infer T>
            ? T
            : never
      }
    : never

/** The names of a record's encrypted fields. */
export type SealedFieldName<R> =
  R extends RecordDeclaration<string, infer F>
    ? {
        [P in keyof F]: F[P] extends SealedField ? P : never
      }[keyof F] &
        string
    : never

/**
 * Check declarations with the engine, with no credentials and no network
 * request. Use it in a test or a continuous integration (CI) step.
 *
 * The `Err` is the first refusal. The error names the record and, where
 * there is one, the field.
 */
export function checkDeclarations(
  declarations: readonly RecordDeclaration[],
): Result<void, RecipherError> {
  if (binding.isErr()) {
    return err(binding.error)
  }
  const native = binding.value
  return settle<void>(() => native.checkDeclarations(declarations))
}
