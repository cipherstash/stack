// The wrapper classes for the scalars JavaScript has no type of its own
// for. Evaluated once per environment by `wrappers.rs`, which keeps the
// classes and recognises instances with `instanceof`.
//
// A wrapper holds its text and nothing else: the text is checked, and the
// scalar built from it, in Rust when the value is encrypted, so one rule
// applies however the instance was made. `value` is an own, enumerable,
// read-only property, so `JSON.stringify`, `structuredClone` and a deep
// equality see it.
//
// Everything the constructor needs from the global object is captured
// here, when the script is evaluated, and the classes, their prototypes and
// every instance are frozen. So a later change to `Object.prototype` or to
// a class (a polluted `writable`, a `Symbol.hasInstance` override) cannot
// make `value` writable, break construction during a decrypt, or turn a
// plain `{ value }` object back into a wrapper.
;(() => {
  // biome-ignore lint/suspicious/noRedundantUseStrict: wrappers.rs runs this file as a classic script, not a module, so the directive is what makes it strict.
  'use strict'
  const defineProperty = Object.defineProperty
  const freeze = Object.freeze
  const getPrototypeOf = Object.getPrototypeOf
  const objectPrototype = Object.prototype
  const apply = Reflect.apply
  // Methods and getters that throw on any receiver but their own type, so a
  // call that returns is a brand check a prototype cannot forge.
  const getter = (proto, name) =>
    Object.getOwnPropertyDescriptor(proto, name).get
  const brands = freeze([
    Map.prototype.has,
    Set.prototype.has,
    WeakMap.prototype.has,
    WeakSet.prototype.has,
    getter(RegExp.prototype, 'source'),
    getter(ArrayBuffer.prototype, 'byteLength'),
    getter(SharedArrayBuffer.prototype, 'byteLength'),
  ])
  const brandCount = brands.length
  const isSlotted = (value) => {
    for (let i = 0; i < brandCount; i++) {
      try {
        apply(brands[i], value, [undefined])
        return true
      } catch {
        // Not this collection type.
      }
    }
    return false
  }
  const define = (name) => {
    const cls = {
      [name]: class {
        constructor(value) {
          if (typeof value !== 'string') {
            throw new TypeError(`${name} takes a string`)
          }
          defineProperty(this, 'value', {
            __proto__: null,
            value,
            enumerable: true,
          })
          freeze(this)
        }
        toJSON() {
          return this.value
        }
        toString() {
          return this.value
        }
        [Symbol.for('nodejs.util.inspect.custom')]() {
          return `${name}(${this.value})`
        }
      },
    }[name]
    freeze(cls.prototype)
    return freeze(cls)
  }
  return freeze({
    __proto__: null,
    VcDate: define('VcDate'),
    VcTimestamp: define('VcTimestamp'),
    VcDecimal: define('VcDecimal'),
    VcUuid: define('VcUuid'),
    // Whether a value is a plain object: prototype `Object.prototype` or
    // `null`. Asked through `Object.getPrototypeOf`, not `napi_get_prototype`,
    // because the latter reads a Proxy's own map and reports `null` for
    // every proxy; this runs the proxy's trap instead, so a proxied Map or
    // Date reports its target's prototype and is refused. A Map, Set,
    // WeakMap, WeakSet, RegExp or ArrayBuffer is refused whatever its
    // prototype: its state is no own property, so given a plain prototype
    // it would read as an empty object.
    isPlain: (value) => {
      const proto = getPrototypeOf(value)
      return (proto === null || proto === objectPrototype) && !isSlotted(value)
    },
  })
})()
