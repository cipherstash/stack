/**
 * The stand-in wrapper classes. The stand-ins replace the addon's classes
 * when the addon did not load. None of these tests needs the addon.
 */
import { inspect } from 'node:util'
import { describe, expect, it } from 'vitest'
import { standInWrapper } from '../../src/values'

const NAMES = ['RcDate', 'RcTimestamp', 'RcDecimal', 'RcUuid'] as const

describe('a stand-in wrapper class', () => {
  it('has the name of the class it stands in for', () => {
    for (const name of NAMES) {
      expect(standInWrapper(name).name).toBe(name)
    }
  })

  it('keeps its text in a read-only, enumerable `value`', () => {
    const RcDate = standInWrapper<{ value: string }>('RcDate')
    const day = new RcDate('2026-11-23')
    expect(Object.getOwnPropertyDescriptor(day, 'value')).toEqual({
      value: '2026-11-23',
      writable: false,
      enumerable: true,
      configurable: false,
    })
    expect(Object.keys(day)).toEqual(['value'])
    expect(Object.isFrozen(day)).toBe(true)
  })

  it('gives its text to String, JSON.stringify and inspect', () => {
    const RcDecimal = standInWrapper<object>('RcDecimal')
    const price = new RcDecimal('1.50')
    expect(String(price)).toBe('1.50')
    expect(JSON.stringify({ price })).toBe('{"price":"1.50"}')
    expect(inspect(price)).toBe('RcDecimal(1.50)')
  })

  it('throws a TypeError for an argument that is not a string', () => {
    const RcDate = standInWrapper<object>('RcDate')
    for (const argument of [20261123, undefined, null, {}, ['2026-11-23']]) {
      // @ts-expect-error: the constructor takes a string.
      expect(() => new RcDate(argument)).toThrow(
        new TypeError('RcDate takes a string'),
      )
    }
  })

  it('is frozen, with a frozen prototype', () => {
    const RcUuid = standInWrapper<object>('RcUuid')
    expect(Object.isFrozen(RcUuid)).toBe(true)
    expect(Object.isFrozen(RcUuid.prototype)).toBe(true)
  })
})
