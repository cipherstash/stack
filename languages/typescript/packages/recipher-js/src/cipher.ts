/**
 * The `Cipher`, `Keyset`, and `Ciphertext` classes of the native addon, with
 * the typed signatures that TypeScript callers see.
 *
 * The classes are written in Rust, in `crate/src/cipher.rs` and
 * `crate/src/ciphertext.rs`. `native.d.ts` declares them as napi-rs
 * generates them: with untyped arguments, and returning outcome objects
 * (`{ ok, value }` or `{ ok, error }`). This module exports the same classes
 * after `adapt` has changed each method to return a `Result`.
 *
 * The signatures below say what each call takes and returns: one string
 * in gives one ciphertext out, and a ciphertext's type parameter is the
 * type it decrypts to.
 */
import { adapt, type Binding, binding, settleAsync } from './binding'
import type { RecipherError } from './error'
import { err, type Result } from './result'

declare const opens: unique symbol

/**
 * One encrypted value: opaque bytes, encrypted with a data key of its own.
 *
 * `T` is the type the ciphertext decrypts to. For example,
 * `keyset.encrypt('..')` returns a `Ciphertext<string>`.
 *
 * `toString()` and Node's `inspect` hide the bytes.
 */
export interface Ciphertext<T = string> {
  /**
   * The bytes to store. The array is a copy, so changing it does not change
   * any ciphertext.
   */
  toBytes(): Uint8Array
  /** Text that names the type and hides the bytes. */
  toString(): string
  /** Carries `T` for the type checker. The property never exists at run time. */
  readonly [opens]?: T
}

/** The `Ciphertext` class. */
export interface CiphertextClass {
  readonly prototype: Ciphertext<unknown>
  /** Whether `value` is a `Ciphertext`, for `value instanceof Ciphertext`. */
  [Symbol.hasInstance](value: unknown): value is Ciphertext<unknown>
  /**
   * Read a ciphertext from stored bytes. This method checks only the shape
   * of the bytes. Decrypting checks that the bytes are genuine and
   * unchanged.
   */
  fromBytes(bytes: Uint8Array): Result<Ciphertext, RecipherError>
}

/**
 * One keyset of a cipher. A keyset is a group of keys in ZeroKMS,
 * CipherStash's key service. Every data key is made under one keyset. A
 * ciphertext names the keyset it was made under.
 */
export interface Keyset {
  /**
   * Encrypt a string as one ciphertext, with a data key of its own and no
   * context. A context is data that a ciphertext is bound to. The ciphertext
   * decrypts only under the same context.
   */
  encrypt(value: string): Promise<Result<Ciphertext<string>, RecipherError>>
  /**
   * Decrypt a ciphertext made under this keyset. A ciphertext from another
   * keyset is an `Err` with the code `stack_encrypt::foreign_keyset`. The
   * keyset refuses it before any key is requested.
   */
  decrypt<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>
  /** Text that names the type. */
  toString(): string
}

/** The `Keyset` class. Get a keyset from `cipher.defaultKeyset()`. */
export interface KeysetClass {
  readonly prototype: Keyset
  /** Whether `value` is a `Keyset`, for `value instanceof Keyset`. */
  [Symbol.hasInstance](value: unknown): value is Keyset
}

/**
 * A cipher: the Stack Encrypt engine, and the keysets it can use.
 *
 * Make one with `Cipher.create()`. In a test, make one with `testCipher()`
 * from `@cipherstash/recipher/testing`.
 */
export interface Cipher {
  /**
   * The client's default keyset: the keyset that a ZeroKMS administrator set
   * for the client. The client is the ZeroKMS client whose credentials the
   * cipher uses. Encrypting needs a keyset.
   */
  defaultKeyset(): Keyset
  /**
   * Decrypt a ciphertext from any of this cipher's keysets, to the type it
   * was encrypted as.
   */
  decrypt<T>(ciphertext: Ciphertext<T>): Promise<Result<T, RecipherError>>
  /** Text that names the type. */
  toString(): string
}

/** The `Cipher` class. */
export interface CipherClass {
  readonly prototype: Cipher
  /** Whether `value` is a `Cipher`, for `value instanceof Cipher`. */
  [Symbol.hasInstance](value: unknown): value is Cipher
  /**
   * Create a cipher that uses ZeroKMS. The cipher looks for credentials in
   * the `CS_*` environment variables, then in the profile that
   * `stash auth login` writes.
   *
   * Resolves to an `Err` with the code `stack_encrypt::config` when there
   * are no credentials.
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
 * Freeze a class, and give it the type that this module declares for it.
 *
 * For a native class, `adapt` has already replaced each method that the type
 * names with a version that returns a `Result`. `type-tests/native.ts`
 * checks that the class has each of those methods. A stand-in class has the
 * static methods that its type names, and no instances.
 */
function retyped<T>(cls: object): T {
  Object.freeze(cls)
  // biome-ignore lint/plugin: the type is the adapted class's, which TypeScript cannot follow through `adapt`.
  return cls as unknown as T
}

/** The native classes, after `adapt` has changed each method to return a `Result`. */
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
 * Stand-in classes for when the native addon did not load. Every call
 * resolves to the `Err` that says why the addon did not load. `instanceof`
 * is false for every value.
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
 * The changed native classes when the addon loaded, or the stand-ins when
 * it did not.
 */
export function classesOf(loaded: Result<Binding, RecipherError>): Classes {
  return loaded.isOk() ? adapted(loaded.value) : missing(loaded.error)
}

/** The classes this package exports. */
export const classes: Classes = classesOf(binding)

/** The `Cipher` class: the native addon's class, with each method returning a `Result`. */
export const Cipher: CipherClass = classes.Cipher
/** The `Keyset` class: the native addon's class, with each method returning a `Result`. */
export const Keyset: KeysetClass = classes.Keyset
/** The `Ciphertext` class: the native addon's class, with each method returning a `Result`. */
export const Ciphertext: CiphertextClass = classes.Ciphertext
