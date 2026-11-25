/**
 * Loads the native addon, and makes each native call return a `Result`.
 *
 * The native addon is the compiled Rust code that Node loads from
 * `recipher.node`. The classes this package exports (`Cipher`, `Keyset`,
 * and `Ciphertext`) are defined in the addon, in Rust. napi-rs, the Rust
 * framework the addon is written with, generates their declarations in
 * `native.d.ts`.
 *
 * A native method takes untyped arguments and checks them itself. A native
 * method does not throw. It returns an outcome object instead: `{ ok, value }`
 * when the call worked, or `{ ok, error }` when it failed.
 *
 * This module does four jobs that the Rust cannot do:
 *
 * - Turn an outcome into a `Result`. Rust cannot build a `Result`, because
 *   `Result` is a TypeScript class.
 * - Turn an exception that napi itself throws into an `Err`, so that no call
 *   throws. napi throws when a method is called on an object that is not an
 *   instance of the method's class.
 * - Bind each method to its instance. A method passed on its own, as in
 *   `stored.map(cipher.decrypt)`, then still has its cipher.
 * - Provide stand-ins that resolve to an `Err` when the addon did not load.
 *   Without the addon, there are no classes to export.
 *
 * `adapt` does the first three jobs. `adapt` replaces each method on a class
 * with a getter. The getter returns the method, bound to its instance, with
 * its outcome turned into a `Result`. `adapt` changes each class once,
 * however many copies of this module load. The ECMAScript module (ESM) build
 * and the CommonJS build share the addon and its classes, because Node loads
 * the addon once per process.
 *
 * The addon is loaded when this module is imported. If the addon does not
 * load, every call returns an `Err` and none throws. The same happens when
 * the addon reports a binding interface version other than this
 * TypeScript's. The binding interface version is a number that the addon and
 * this TypeScript both state, and the two numbers must match.
 */
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type * as Native from '../native'
import type { Outcome } from '../native'
import { fromNative, type RecipherError, sdkError } from './error'
import { err, ok, type Result } from './result'

/**
 * The binding interface version of this TypeScript. The addon must report
 * the same number.
 */
export const BINDING_INTERFACE = 2

/** The native addon's exports, as `native.d.ts` declares them. */
export type Binding = typeof Native

/** The exports that `load` checks the addon has. */
const EXPORTS = [
  'Cipher',
  'Keyset',
  'Ciphertext',
  'bindingInterface',
  'createTesting',
] as const

/**
 * Load the native addon at `path` with `require`. Then check that this
 * TypeScript can call it: the addon must export every name in `EXPORTS`, and
 * report the binding interface version `BINDING_INTERFACE`.
 */
export function load(
  require: (path: string) => unknown,
  path: string,
): Result<Binding, RecipherError> {
  let exported: unknown
  try {
    exported = require(path)
  } catch {
    return err(
      sdkError(
        'recipher_js::load',
        `the native build of @cipherstash/recipher did not load from ${path}. ` +
          'Build it with `pnpm --filter @cipherstash/recipher build:debug`.',
      ),
    )
  }
  if (
    typeof exported !== 'object' ||
    exported === null ||
    !EXPORTS.every(
      (name) => typeof Reflect.get(exported as object, name) === 'function',
    )
  ) {
    return err(
      sdkError(
        'recipher_js::load',
        'the native build of @cipherstash/recipher does not export its classes',
      ),
    )
  }
  // The check above found a function for every name in `EXPORTS`, as
  // `Binding` declares.
  const binding = exported as Binding
  let version: unknown
  try {
    version = binding.bindingInterface()
  } catch {
    version = undefined
  }
  if (version !== BINDING_INTERFACE) {
    return err(
      sdkError(
        'recipher_js::binding_interface',
        `the native build implements binding interface ${String(version)}, ` +
          `and this TypeScript needs ${BINDING_INTERFACE}`,
      ),
    )
  }
  return ok(binding)
}

/** This package's native addon, loaded once, when this module is imported. */
export const binding: Result<Binding, RecipherError> = load(
  createRequire(import.meta.url),
  join(dirname(fileURLToPath(import.meta.url)), '..', 'recipher.node'),
)

/**
 * The error for a native call that threw or rejected. A native call should
 * never do either.
 */
function threw(): RecipherError {
  return sdkError(
    'recipher_js::native_threw',
    'a call into the native build threw. A method called on something that ' +
      'is not its class does; otherwise, report this as a bug in @cipherstash/recipher.',
  )
}

/** Turn a native outcome into a `Result`. */
function fromOutcome<T>(outcome: Outcome<unknown>): Result<T, RecipherError> {
  if (typeof outcome !== 'object' || outcome === null) {
    return err(
      sdkError(
        'recipher_js::outcome',
        'the native build returned something that is not an outcome',
      ),
    )
  }
  // `native.d.ts` gives `value` a type for each method. Here the type comes
  // from the typed signature over the method, which names `T`.
  return outcome.ok ? ok(outcome.value as T) : err(fromNative(outcome.error))
}

/** Run a synchronous native call, and return its `Result`. Never throws. */
export function settle<T>(
  call: () => Outcome<unknown>,
): Result<T, RecipherError> {
  try {
    return fromOutcome(call())
  } catch {
    return err(threw())
  }
}

/** Run an asynchronous native call, and return its `Result`. Never rejects. */
export async function settleAsync<T>(
  call: () => Promise<Outcome<unknown>>,
): Promise<Result<T, RecipherError>> {
  try {
    return fromOutcome(await call())
  } catch {
    return err(threw())
  }
}

/** How `adapt` changes what a method returns to the caller. */
export type Adaptation =
  /** A promise of an outcome becomes a promise of a `Result`. */
  | 'async'
  /** An outcome becomes a `Result`. */
  | 'sync'
  /**
   * The return value is unchanged, because the method does not fail. The
   * method is only bound to its instance.
   */
  | 'plain'

/** The marker that `adapt` sets on a class or a prototype it has changed. */
const ADAPTED = Symbol.for('@cipherstash/recipher.adapted')

/**
 * Replace each method named in `methods` on `target` with a getter. Then
 * freeze `target`.
 *
 * `target` is a class, for its static methods, or a class's prototype. The
 * getter returns the method bound to the object it is read from. The bound
 * method returns a `Result` in place of an outcome, as `methods` says. If
 * `adapt` has already changed `target`, `adapt` leaves it as it is.
 */
export function adapt(
  target: object,
  methods: Readonly<Record<string, Adaptation>>,
): void {
  if (Object.hasOwn(target, ADAPTED)) {
    return
  }
  for (const [name, how] of Object.entries(methods)) {
    const raw: unknown = Reflect.get(target, name)
    if (typeof raw !== 'function') {
      continue
    }
    const wrap = (self: unknown) => {
      const call = (args: unknown[]) => () => Reflect.apply(raw, self, args)
      switch (how) {
        case 'async':
          return (...args: unknown[]) => settleAsync(call(args))
        case 'sync':
          return (...args: unknown[]) => settle(call(args))
        case 'plain':
          return (...args: unknown[]) => call(args)()
      }
    }
    const bound = new WeakMap<object, unknown>()
    Object.defineProperty(target, name, {
      configurable: false,
      enumerable: false,
      get(this: unknown) {
        if (typeof this !== 'object' && typeof this !== 'function') {
          return wrap(this)
        }
        if (this === null) {
          return wrap(this)
        }
        let method = bound.get(this)
        if (method === undefined) {
          method = wrap(this)
          bound.set(this, method)
        }
        return method
      },
    })
  }
  Object.defineProperty(target, ADAPTED, { value: true })
  Object.freeze(target)
}
