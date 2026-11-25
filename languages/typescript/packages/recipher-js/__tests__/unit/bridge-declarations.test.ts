/**
 * The value bridge's declarations against its JavaScript.
 *
 * `value-napi/src/wrappers.d.ts` declares the classes that
 * `value-napi/src/wrappers.js` defines. This suite evaluates the script as
 * the bridge does, and checks that each class has the members the file
 * declares, and no others. The `check` lines are compiled by `tsc`, which
 * `test` also runs.
 *
 * The bridge's list of kinds is checked against the engine's kinds by a
 * Rust test, in `crate/src/ciphertext.rs`.
 */
import { readFileSync } from 'node:fs'
import { runInThisContext } from 'node:vm'
import { describe, expect, it } from 'vitest'
import type {
  VcDate,
  VcDecimal,
  VcTimestamp,
  VcUuid,
  WrapperClasses,
  Wrappers,
} from '../../value-napi/src/wrappers'

type Equal<A, B> =
  (<X>() => X extends A ? 1 : 2) extends <X>() => X extends B ? 1 : 2
    ? true
    : false
function check<_ extends true>(): void {}

/** The classes, by the names the declarations give them. */
const CLASSES = ['VcDate', 'VcTimestamp', 'VcDecimal', 'VcUuid'] as const
check<Equal<(typeof CLASSES)[number], keyof WrapperClasses>>()

/** The members each instance declares, apart from the type-only marker. */
const MEMBERS = ['toJSON', 'toString', 'value'] as const
type Members = (typeof MEMBERS)[number]
type Declared<W> = Extract<keyof W, string>
check<Equal<Declared<VcDate>, Members>>()
check<Equal<Declared<VcTimestamp>, Members>>()
check<Equal<Declared<VcDecimal>, Members>>()
check<Equal<Declared<VcUuid>, Members>>()

const source = readFileSync(
  new URL('../../value-napi/src/wrappers.js', import.meta.url),
  'utf8',
)
// The script's value is the object the bridge keeps: the declarations say
// it is a `Wrappers`, and the tests below check that it is.
const script: Wrappers = runInThisContext(source)

describe('wrappers.js against wrappers.d.ts', () => {
  it('returns the declared classes and the plain-object check, frozen', () => {
    expect(Object.keys(script).sort()).toEqual([...CLASSES, 'isPlain'].sort())
    expect(Object.isFrozen(script)).toBe(true)
  })

  it('answers the plain-object check', () => {
    expect(script.isPlain({})).toBe(true)
    expect(script.isPlain(Object.create(null))).toBe(true)
    expect(script.isPlain(new Map())).toBe(false)
    expect(script.isPlain([])).toBe(false)
  })

  for (const name of CLASSES) {
    describe(name, () => {
      const Class = script[name]

      it('is the class of its name, frozen', () => {
        expect(Class.name).toBe(name)
        expect(Object.isFrozen(Class)).toBe(true)
        expect(Object.isFrozen(Class.prototype)).toBe(true)
      })

      it('has the declared members, and no others', () => {
        const instance = new Class('text')
        const own = Object.getOwnPropertyNames(instance)
        const inherited = Object.getOwnPropertyNames(Class.prototype).filter(
          (member) => member !== 'constructor',
        )
        expect([...own, ...inherited].sort()).toEqual([...MEMBERS])
        // The one member not declared: Node's inspect hook, whose key
        // TypeScript has no type for.
        expect(Object.getOwnPropertySymbols(Class.prototype)).toEqual([
          Symbol.for('nodejs.util.inspect.custom'),
        ])
      })

      it('keeps its text in an own, enumerable, read-only `value`', () => {
        const instance = new Class('text')
        expect(Object.getOwnPropertyDescriptor(instance, 'value')).toEqual({
          value: 'text',
          writable: false,
          enumerable: true,
          configurable: false,
        })
        expect(Object.isFrozen(instance)).toBe(true)
        expect(instance).toBeInstanceOf(Class)
        expect(Object.getPrototypeOf(instance)).toBe(Class.prototype)
      })

      it('returns its text from `toJSON` and `toString`', () => {
        const instance = new Class('text')
        expect(instance.toJSON()).toBe('text')
        expect(instance.toString()).toBe('text')
        expect(JSON.stringify({ instance })).toBe('{"instance":"text"}')
      })

      it('throws a TypeError for text that is not a string', () => {
        const construct = Class as unknown as new (text: unknown) => unknown
        expect(() => new construct(5)).toThrow(TypeError)
      })
    })
  }
})
