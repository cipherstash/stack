/**
 * The native build, and the one job the TypeScript does over it: make each
 * native call a `Result`.
 *
 * The classes the package exports (`Cipher`, `Keyset`, `Ciphertext`) are the
 * native build's own, written in Rust, and `native.d.ts` is what napi-rs
 * generates for them. A native method takes untyped arguments and checks
 * them itself, and returns an outcome object, `{ ok, value }` or
 * `{ ok, error }`, rather than throwing. What is left for TypeScript:
 *
 * - turning an outcome into a `Result`, which Rust cannot build because
 *   `Result` is a TypeScript class;
 * - turning what napi itself throws (a method called on something that is
 *   not its class) into an `Err`, so no call throws;
 * - binding each method to its instance, so a method passed on its own,
 *   as in `stored.map(cipher.decrypt)`, still has its cipher;
 * - stand-ins that resolve to an `Err` when the native build did not load,
 *   since then there are no classes to export.
 *
 * `adapt` does the first three by replacing each method on a class with a
 * getter that returns the method, bound and wrapped. It runs once per class,
 * however many copies of this module load it: the ESM and the CommonJS build
 * share the addon, which Node loads once per process, and its classes.
 *
 * The addon is loaded when this module is imported. A build that does not
 * load, or that implements another binding interface than this TypeScript,
 * is an `Err` from every call, never an exception.
 */
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type * as Native from '../native'
import type { Outcome } from '../native'
import { fromNative, internal, type RecipherError } from './error'
import { err, ok, type Result } from './result'

/** The binding interface this TypeScript speaks. */
export const BINDING_INTERFACE = 1

/** What the native build exports. */
export type Binding = typeof Native

/** The exports `load` checks for. */
const EXPORTS = [
  'Cipher',
  'Keyset',
  'Ciphertext',
  'bindingInterface',
  'createTesting',
] as const

/**
 * Load the native build at `path` with `require`, and check that it is one
 * this TypeScript can call.
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
      internal(
        'recipher::load',
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
      internal(
        'recipher::load',
        'the native build of @cipherstash/recipher does not export its classes',
      ),
    )
  }
  // Every export `EXPORTS` names is a function, as `Binding` says.
  const binding = exported as Binding
  let version: unknown
  try {
    version = binding.bindingInterface()
  } catch {
    version = undefined
  }
  if (version !== BINDING_INTERFACE) {
    return err(
      internal(
        'recipher::binding_interface',
        `the native build implements binding interface ${String(version)}, ` +
          `and this TypeScript needs ${BINDING_INTERFACE}`,
      ),
    )
  }
  return ok(binding)
}

/** The native build of this package, loaded once, when it is imported. */
export const binding: Result<Binding, RecipherError> = load(
  createRequire(import.meta.url),
  join(dirname(fileURLToPath(import.meta.url)), '..', 'recipher.node'),
)

/** The error of a native call that threw or rejected, which it never should. */
function threw(): RecipherError {
  return internal(
    'recipher::threw',
    'a call into the native build threw. A method called on something that ' +
      'is not its class does; otherwise, report this as a bug in @cipherstash/recipher.',
  )
}

/** The `Result` of a native outcome. */
function fromOutcome<T>(outcome: Outcome<unknown>): Result<T, RecipherError> {
  if (typeof outcome !== 'object' || outcome === null) {
    return err(
      internal(
        'recipher::outcome',
        'the native build returned something that is not an outcome',
      ),
    )
  }
  // The native build's declarations type `value` for each method; the
  // typed signature over the method names `T`.
  return outcome.ok ? ok(outcome.value as T) : err(fromNative(outcome.error))
}

/** A synchronous native call as a `Result`. Never throws. */
export function settle<T>(
  call: () => Outcome<unknown>,
): Result<T, RecipherError> {
  try {
    return fromOutcome(call())
  } catch {
    return err(threw())
  }
}

/** An asynchronous native call as a `Result`. Never rejects. */
export async function settleAsync<T>(
  call: () => Promise<Outcome<unknown>>,
): Promise<Result<T, RecipherError>> {
  try {
    return fromOutcome(await call())
  } catch {
    return err(threw())
  }
}

/** How a method's return value reaches the caller. */
export type Adaptation =
  /** A promise of an outcome, as a promise of a `Result`. */
  | 'async'
  /** An outcome, as a `Result`. */
  | 'sync'
  /** As it is: the method does not fail. Only bound. */
  | 'plain'

/** Set on a class or a prototype `adapt` has run on. */
const ADAPTED = Symbol.for('@cipherstash/recipher.adapted')

/**
 * Replace each method named in `methods` on `target` (a class, for its
 * static methods, or its prototype) with a getter that gives the method
 * bound to the object it is read from, its outcome a `Result`. Then freeze
 * `target`. A target already adapted is left as it is.
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
