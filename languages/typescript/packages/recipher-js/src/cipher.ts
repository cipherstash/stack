/**
 * The `Cipher`, `Keyset`, and `Ciphertext` classes.
 *
 * The classes are the native addon's, written in Rust in `crate/`. The
 * classes' types are the ones napi-rs generates in `native.d.ts`. Each native
 * method returns a `Result` itself.
 *
 * This module adds two things that Rust cannot:
 *
 * - Stand-in classes for when the addon did not load. Every call on them
 *   resolves to the `Err` that says why.
 * - Class types without a constructor. napi-rs declares a class that has
 *   no constructor as one that `new` can call, and calling it throws.
 */
import type * as Native from '../native'
import { type Binding, binding } from './binding'
import type { RecipherError } from './error'
import { err, type Result } from './result'

/**
 * One encrypted value: opaque bytes, encrypted with a data key of its own.
 *
 * `T` is the type the ciphertext decrypts to. For example,
 * `keyset.encrypt('..')` returns a `Ciphertext<string>`.
 */
export type Ciphertext<T = string> = Native.Ciphertext<T>
/** A cipher: the Stack Encrypt engine, and the keysets it can use. */
export type Cipher = Native.Cipher
/** One keyset of a cipher. A keyset is a group of keys in ZeroKMS. */
export type Keyset = Native.Keyset

/**
 * A native class's static side, without the constructor: its static
 * methods, its prototype, and `instanceof`.
 */
type Static<C extends abstract new () => object> = Omit<C, never> & {
  /** Whether `value` is an instance of the class, for `instanceof`. */
  [Symbol.hasInstance](value: unknown): value is InstanceType<C>
}

/** The `Cipher` class. Get a cipher from `Cipher.create()`. */
export type CipherClass = Static<typeof Native.Cipher>
/** The `Keyset` class. Get a keyset from `cipher.defaultKeyset()`. */
export type KeysetClass = Static<typeof Native.Keyset>
/** The `Ciphertext` class. */
export type CiphertextClass = Static<typeof Native.Ciphertext>

/** The classes, as this package exports them. */
export interface Classes {
  Cipher: CipherClass
  Keyset: KeysetClass
  Ciphertext: CiphertextClass
  createTesting: Binding['createTesting']
}

/**
 * Give a class its type without a constructor. The class is the native
 * class, or a stand-in. TypeScript types a function's `Symbol.hasInstance`
 * as returning a `boolean`. So TypeScript does not know that `instanceof`
 * narrows a value to the class's instances, and this cast tells it.
 */
function typed<T>(cls: object): T {
  // biome-ignore lint/plugin: the class's `instanceof` narrows to its instances. A function's `boolean` `Symbol.hasInstance` cannot say so.
  return cls as unknown as T
}

/** The native classes. */
function native(loaded: Binding): Classes {
  return {
    Cipher: typed<CipherClass>(loaded.Cipher),
    Keyset: typed<KeysetClass>(loaded.Keyset),
    Ciphertext: typed<CiphertextClass>(loaded.Ciphertext),
    createTesting: loaded.createTesting,
  }
}

/**
 * Stand-in classes for when the native addon did not load. Every call
 * resolves to the `Err` that says why the addon did not load. `instanceof`
 * is false for every value.
 */
function missing(error: RecipherError): Classes {
  const stand = <T>(cls: object): T => typed<T>(Object.freeze(cls))
  return {
    Cipher: stand<CipherClass>(
      // biome-ignore lint/complexity/noStaticOnlyClass: a stand-in for a class, so `instanceof` still works.
      class Cipher {
        static create() {
          return Promise.resolve(err(error))
        }
      },
    ),
    Keyset: stand<KeysetClass>(class Keyset {}),
    Ciphertext: stand<CiphertextClass>(
      // biome-ignore lint/complexity/noStaticOnlyClass: a stand-in for a class, so `instanceof` still works.
      class Ciphertext {
        static fromBytes() {
          return err(error)
        }
      },
    ),
    createTesting: () => Promise.resolve(err(error)),
  }
}

/**
 * The native classes when the addon loaded, or the stand-ins when it did
 * not.
 */
export function classesOf(loaded: Result<Binding, RecipherError>): Classes {
  return loaded.isOk() ? native(loaded.value) : missing(loaded.error)
}

/** The classes this package exports. */
export const classes: Classes = classesOf(binding)

/** The `Cipher` class: the native addon's class. */
export const Cipher: CipherClass = classes.Cipher
/** The `Keyset` class: the native addon's class. */
export const Keyset: KeysetClass = classes.Keyset
/** The `Ciphertext` class: the native addon's class. */
export const Ciphertext: CiphertextClass = classes.Ciphertext
