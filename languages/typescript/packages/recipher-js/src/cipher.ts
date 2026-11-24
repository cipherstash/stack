/**
 * `Cipher`, `Keyset` and `Ciphertext`: the native build's classes, with the
 * typed signatures TypeScript callers see.
 *
 * The classes are written in Rust (`crate/src/cipher.rs` and
 * `crate/src/ciphertext.rs`), and `native.d.ts` declares them as napi-rs
 * generates them: untyped arguments, outcome objects. This module exports
 * the same classes, adapted by `adapt` so each method returns a `Result`,
 * under the signatures below, which say what a call takes and gives: one
 * value in and one ciphertext out, and the type a ciphertext opens as.
 */
import { adapt, type Binding, binding, settleAsync } from './binding'
import type { RecipherError } from './error'
import { err, type Result } from './result'

declare const opens: unique symbol

/**
 * One sealed value: opaque bytes, with its own data key.
 *
 * `T` is the type it decrypts to: `keyset.encrypt('..')` returns a
 * `Ciphertext<string>`. `toString()` and Node's `inspect` hide the bytes.
 */
export interface Ciphertext<T = string> {
  /** The bytes to store. A copy: changing it changes no ciphertext. */
  toBytes(): Uint8Array
  /** Names the type and hides the bytes. */
  toString(): string
  /** Records `T`, which nothing at run time holds. */
  readonly [opens]?: T
}

/** The `Ciphertext` class. */
export interface CiphertextClass {
  readonly prototype: Ciphertext<unknown>
  /** `value instanceof Ciphertext`. */
  [Symbol.hasInstance](value: unknown): value is Ciphertext<unknown>
  /**
   * Read a ciphertext from stored bytes. This checks the bytes' shape only;
   * decrypting is what authenticates them.
   */
  fromBytes(bytes: Uint8Array): Result<Ciphertext<string>, RecipherError>
}

/**
 * One keyset of a cipher. Every data key is made under one keyset, and a
 * ciphertext names the keyset it was made under.
 */
export interface Keyset {
  /**
   * Encrypt a value, with no context, as one ciphertext with its own data
   * key.
   */
  encrypt(value: string): Promise<Result<Ciphertext<string>, RecipherError>>
  /**
   * Open a ciphertext sealed under this keyset. A ciphertext from another
   * keyset is an `Err` of kind `foreign_keyset`, refused before any key is
   * requested.
   */
  decrypt<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>
  /** Names the type. */
  toString(): string
}

/** The `Keyset` class. Get a keyset from `cipher.defaultKeyset()`. */
export interface KeysetClass {
  readonly prototype: Keyset
  /** `value instanceof Keyset`. */
  [Symbol.hasInstance](value: unknown): value is Keyset
}

/**
 * A cipher: the engine, and the keysets it reaches.
 *
 * Build one with `Cipher.create()`, or, in a test, with `testCipher()` from
 * `@cipherstash/recipher/testing`.
 */
export interface Cipher {
  /**
   * The client's default keyset: the one a ZeroKMS administrator set for
   * it. Encrypting needs a keyset.
   */
  defaultKeyset(): Keyset
  /** Open a ciphertext from any of this cipher's keysets. */
  decrypt<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>
  /** Names the type. */
  toString(): string
}

/** The `Cipher` class. */
export interface CipherClass {
  readonly prototype: Cipher
  /** `value instanceof Cipher`. */
  [Symbol.hasInstance](value: unknown): value is Cipher
  /**
   * A cipher over ZeroKMS, with the credentials it finds: the `CS_*`
   * variables, then the profile that `stash auth login` writes. Resolves
   * to an `Err` of kind `credential` when there are none.
   */
  create(): Promise<Result<Cipher, RecipherError>>
}

/** The classes, as this package exports them. */
export interface Classes {
  Cipher: CipherClass
  Keyset: KeysetClass
  Ciphertext: CiphertextClass
  createTesting(seed: unknown): Promise<Result<Cipher, RecipherError>>
}

/**
 * A class, frozen, under the type this module gives it. For a native class,
 * `adapt` has replaced each method the type names with its form that
 * returns a `Result`; `type-tests/native.ts` checks that each is a method
 * the class has. A stand-in has the static methods its type names, and no
 * instances.
 */
function retyped<T>(cls: object): T {
  Object.freeze(cls)
  // biome-ignore lint/plugin: the type is the adapted class's, which TypeScript cannot follow through `adapt`.
  return cls as unknown as T
}

/** The native classes, adapted so each method returns a `Result`. */
function adapted(native: Binding): Classes {
  adapt(native.Cipher, { create: 'async' })
  adapt(native.Cipher.prototype, {
    defaultKeyset: 'plain',
    decrypt: 'async',
  })
  adapt(native.Keyset.prototype, { encrypt: 'async', decrypt: 'async' })
  adapt(native.Ciphertext, { fromBytes: 'sync' })
  adapt(native.Ciphertext.prototype, { toBytes: 'plain' })
  return {
    Cipher: retyped<CipherClass>(native.Cipher),
    Keyset: retyped<KeysetClass>(native.Keyset),
    Ciphertext: retyped<CiphertextClass>(native.Ciphertext),
    createTesting: (seed) =>
      settleAsync<Cipher>(() => native.createTesting(seed)),
  }
}

/**
 * Stand-ins for a native build that did not load: every call resolves to
 * the `Err` that says why, and `instanceof` is false for every value.
 */
function missing(error: RecipherError): Classes {
  return {
    Cipher: retyped<CipherClass>(
      // biome-ignore lint/complexity/noStaticOnlyClass: a stand-in for a class, so `instanceof` still works.
      class Cipher {
        static create() {
          return Promise.resolve(err(error))
        }
      },
    ),
    Keyset: retyped<KeysetClass>(class Keyset {}),
    Ciphertext: retyped<CiphertextClass>(
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
 * The classes for a native build, or the stand-ins for one that did not
 * load.
 */
export function classesOf(loaded: Result<Binding, RecipherError>): Classes {
  return loaded.isOk() ? adapted(loaded.value) : missing(loaded.error)
}

/** The classes this package exports. */
export const classes: Classes = classesOf(binding)

/** The `Cipher` class: the native build's, adapted. */
export const Cipher: CipherClass = classes.Cipher
/** The `Keyset` class: the native build's, adapted. */
export const Keyset: KeysetClass = classes.Keyset
/** The `Ciphertext` class: the native build's, adapted. */
export const Ciphertext: CiphertextClass = classes.Ciphertext
