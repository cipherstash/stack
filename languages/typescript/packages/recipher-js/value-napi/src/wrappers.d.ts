/**
 * The TypeScript declarations of the wrapper classes that `wrappers.js`
 * defines: `VcDate`, `VcTimestamp`, `VcDecimal` and `VcUuid`. Each class
 * holds the text of a value that JavaScript has no type for.
 *
 * `wrappers.js` is a script, not a module. The bridge evaluates it once per
 * environment, and an addon exports the classes it returns by name. So this
 * file declares types only: import it with `import type`. A value import
 * would load `wrappers.js` as a module, which exports nothing.
 *
 * A test in the package (`__tests__/unit/bridge-declarations.test.ts`)
 * evaluates `wrappers.js` and checks it against this file.
 */

declare const wrapper: unique symbol

/**
 * An instance of the wrapper class `Name`. `wrappers.js` makes every class
 * the same way, so the four share these members. An instance is frozen.
 *
 * The prototype also has Node's `inspect` hook, which shows the class name
 * and the text. It is not declared: its key is `Symbol.for(..)`, and
 * TypeScript has no type for such a key.
 */
export interface WrapperInstance<Name extends string> {
  /** The text. An own, enumerable, read-only property. */
  readonly value: string
  /** Returns the text, so `JSON.stringify` writes the text. */
  toJSON(): string
  /** Returns the text. */
  toString(): string
  /**
   * Keeps the classes apart for the type checker, which compares types by
   * their members. The property never exists at run time.
   */
  readonly [wrapper]: Name
}

/** A calendar date, such as `new VcDate('2026-11-23')`. The text is `YYYY-MM-DD`. */
export interface VcDate extends WrapperInstance<'VcDate'> {}

/** A UTC instant, to the nanosecond. The text is RFC 3339, with nanoseconds. */
export interface VcTimestamp extends WrapperInstance<'VcTimestamp'> {}

/** A decimal with its scale, such as `new VcDecimal('1.50')`. The text keeps the scale. */
export interface VcDecimal extends WrapperInstance<'VcDecimal'> {}

/** A universally unique identifier (UUID). The text is hyphenated hex. */
export interface VcUuid extends WrapperInstance<'VcUuid'> {}

/**
 * A wrapper class. `new` takes the text, and throws a `TypeError` when the
 * text is not a string. The text is checked when the value is encrypted,
 * not here.
 */
export interface WrapperConstructor<W> {
  new (text: string): W
  readonly prototype: W
}

/** The wrapper classes by name, as an addon exports them. */
export interface WrapperClasses {
  readonly VcDate: WrapperConstructor<VcDate>
  readonly VcTimestamp: WrapperConstructor<VcTimestamp>
  readonly VcDecimal: WrapperConstructor<VcDecimal>
  readonly VcUuid: WrapperConstructor<VcUuid>
}

/**
 * What `wrappers.js` returns: the classes, and the plain-object check the
 * bridge uses when it reads a value. The object is frozen.
 */
export interface Wrappers extends WrapperClasses {
  /**
   * Whether `value` is a plain object: its prototype is `Object.prototype`
   * or `null`, and it is not a `Map`, `Set`, `WeakMap`, `WeakSet`,
   * `RegExp`, `ArrayBuffer` or `SharedArrayBuffer`.
   */
  readonly isPlain: (value: object) => boolean
}
