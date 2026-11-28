/**
 * Loads the native addon, and gives it the classes that its calls return.
 *
 * The native addon is the compiled Rust code that Node loads from
 * `recipher.node`. The addon defines the classes this package exports:
 * `Cipher`, `Keyset`, and `Ciphertext`. napi-rs is the Rust framework the
 * addon is written with. napi-rs writes the classes' declarations to
 * `native.d.ts`. Those declarations are the package's public types.
 *
 * A native method returns a `Result` itself. Rust cannot define `Ok`,
 * `Err`, or `RecipherError`, because they are TypeScript classes. So this
 * module gives the three classes to the addon when it loads it
 * (`installResult`).
 *
 * Node loads the addon once per process. The ECMAScript module (ESM) build
 * and the CommonJS build of this package share it. The first build to load
 * installs its classes, and the addon keeps them.
 *
 * The addon is loaded when this module is imported. If the addon does not
 * load, every call returns an `Err` and none throws. The same happens when
 * the addon reports a binding interface version other than this
 * TypeScript's. The binding interface version is a number that the addon
 * and this TypeScript both state. The two numbers must match.
 */
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import type * as Native from '../native'
import { RecipherError, sdkError } from './error'
import { Err, err, Ok, ok, type Result } from './result'

/**
 * The binding interface version of this TypeScript. The addon must report
 * the same number.
 */
export const BINDING_INTERFACE = 1

/** The native addon's exports, as `native.d.ts` declares them. */
export type Binding = typeof Native

/** The exports that `load` checks the addon has. */
const EXPORTS = [
  'Cipher',
  'Keyset',
  'Ciphertext',
  'Json',
  'bindingInterface',
  'checkDeclarations',
  'createTesting',
  'installResult',
  'json',
  'RcDate',
  'RcTimestamp',
  'RcDecimal',
  'RcUuid',
] as const

/**
 * Load the native addon at `path` with `require`. Then check that this
 * TypeScript can call it: the addon must export every name in `EXPORTS`, and
 * report the binding interface version `BINDING_INTERFACE`. Then give the
 * addon the classes of a `Result`, and freeze its classes.
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
  try {
    binding.installResult({ Ok, Err, RecipherError })
  } catch {
    return err(
      sdkError(
        'recipher_js::load',
        'the native build of @cipherstash/recipher refused the Result classes',
      ),
    )
  }
  for (const cls of [
    binding.Cipher,
    binding.Keyset,
    binding.Ciphertext,
    binding.Json,
  ]) {
    Object.freeze(cls.prototype)
    Object.freeze(cls)
  }
  return ok(binding)
}

/** This package's native addon, loaded once, when this module is imported. */
export const binding: Result<Binding, RecipherError> = load(
  createRequire(import.meta.url),
  join(dirname(fileURLToPath(import.meta.url)), '..', 'recipher.node'),
)
