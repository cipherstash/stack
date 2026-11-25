/**
 * The types of record declarations, rows, stored rows and `Cipher.create`'s
 * options.
 *
 * This module holds types only, and imports types only. The addon's
 * generated declarations (`native.d.ts`) name these types in their
 * signatures, so a module here that loaded the addon would make the
 * declarations import themselves.
 */
import type { Kind, ValueOf } from './kinds'

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

/** Options for `Cipher.create`. */
export interface CipherOptions {
  /**
   * Records to check when the cipher is created, before any credentials are
   * looked for. A declaration that the engine refuses then gives an `Err`
   * here, not at its first use.
   */
  records?: readonly RecordDeclaration[]
}
