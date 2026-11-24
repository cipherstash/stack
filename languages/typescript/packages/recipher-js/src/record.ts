/**
 * Records: a declaration of fields, each encrypted, encrypted and indexed,
 * or passed through.
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
 * A declaration is plain, frozen data: `{ type: 'record', name, fields }`,
 * each field with its own declaration. The native build reads it, builds
 * the engine's plan from it once, and checks it then: when a cipher first
 * uses it, or when `Cipher.create({ records })` or `checkDeclarations(..)`
 * is called. The types below are what TypeScript checks a row against.
 */
import { binding, settle } from './binding'
import type { RecipherError } from './error'
import type { Kind, ValueOf } from './kinds'
import { err, type Result } from './result'

/** An index a sealed field stores beside its ciphertext. */
export type Index = 'equality' | 'match' | 'ore' | 'ope'

/**
 * How a field stores a value that is not there.
 *
 * - `sealed`: the null is sealed like a value, as long as one, so the
 *   stored row does not show which rows have none. For a field of fixed
 *   width (a boolean, a number, a date, a timestamp or a decimal) whose
 *   only index is `equality`.
 * - `sql`: the stored row has `null` for the field, as SQL `NULL` does.
 */
export type NullMode = 'sealed' | 'sql'

/** A field that is encrypted, and indexed if it names indexes. */
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
 * A field passed through as it is: **not encrypted and not
 * authenticated.** Anyone with the stored row can read it, change it or
 * remove it, and the sealed fields still decrypt. Use it only for values
 * that are not secret, and treat the value read back as untrusted.
 */
export interface PassthroughField<T = unknown> {
  readonly type: 'passthrough'
  /** Records `T`, which nothing at run time holds. */
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
  /** How the field stores a null. With none, every row needs a value. */
  null?: N
}

/** An encrypted field of `kind`. */
export function encrypt<
  K extends Kind,
  const I extends readonly Index[] = readonly [],
  N extends NullMode | undefined = undefined,
>(
  kind: K,
  options: SealedOptions<I, N> = {},
  // `NoInfer`: what a field declares is read from `options` alone, never from
  // the type a caller's context expects, which names every index and mode.
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

/** A record's declaration: plain, frozen data. */
export interface RecordDeclaration<
  Name extends string = string,
  F extends { readonly [field: string]: Field } = {
    readonly [field: string]: Field
  },
> {
  /** Marks a declaration, for every copy of the package. */
  readonly type: 'record'
  /** The record's name: the first part of each field's context. */
  readonly name: Name
  /** The fields, each with its declaration. */
  readonly fields: F
}

/**
 * A record named `name`, with `fields`. Each field's context is its field
 * path: the record's name, then the field's name.
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

/** The plaintext row of a record. A field that takes a null may be `null`. */
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

/** A sealed field as it is stored: its ciphertext and its index terms. */
export type StoredField<I extends readonly Index[] = readonly Index[]> = {
  readonly ciphertext: Uint8Array
} & { readonly [X in I[number]]: Uint8Array }

/**
 * The stored row of a record: for each sealed field its ciphertext and
 * terms, each opaque bytes; for each passthrough field its value. A field
 * that stores a null as SQL `NULL` is `null` for an absent value.
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

/** The field names of a record whose fields are sealed. */
export type SealedFieldName<R> =
  R extends RecordDeclaration<string, infer F>
    ? {
        [P in keyof F]: F[P] extends SealedField ? P : never
      }[keyof F] &
        string
    : never

/**
 * Check declarations with the engine, with no credentials and no request:
 * for a test or a CI step. The first refusal is the `Err`, naming the
 * record and, where there is one, the field.
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
