import { describe, expect, it } from 'vitest'
import { Err, err, Ok, ok, type Result } from '../../src/result'

const good: Result<number, string> = ok(2)
const bad: Result<number, string> = err('failed')

describe('Result', () => {
  it('narrows with isOk and isErr', () => {
    expect(good.isOk()).toBe(true)
    expect(good.isErr()).toBe(false)
    expect(bad.isOk()).toBe(false)
    expect(bad.isErr()).toBe(true)
    if (good.isOk()) {
      expect(good.value).toBe(2)
    }
    if (bad.isErr()) {
      expect(bad.error).toBe('failed')
    }
    expect(good).toBeInstanceOf(Ok)
    expect(bad).toBeInstanceOf(Err)
  })

  it('has ok and err, which give undefined for the other case', () => {
    expect(good.ok()).toBe(2)
    expect(good.err()).toBeUndefined()
    expect(bad.ok()).toBeUndefined()
    expect(bad.err()).toBe('failed')
  })

  it('maps the value or the error', () => {
    expect(good.map((n) => n * 10).unwrap()).toBe(20)
    expect(bad.map((n) => n * 10).err()).toBe('failed')
    expect(good.mapErr((e) => e.length).unwrap()).toBe(2)
    expect(bad.mapErr((e) => e.length).err()).toBe(6)
    expect(good.mapOr(0, (n) => n + 1)).toBe(3)
    expect(bad.mapOr(0, (n) => n + 1)).toBe(0)
  })

  it('combines with and, andThen, or and orElse', () => {
    const other: Result<string, string> = ok('other')
    expect(good.and(other).unwrap()).toBe('other')
    expect(bad.and(other).err()).toBe('failed')
    expect(good.andThen((n) => ok(n + 1)).unwrap()).toBe(3)
    expect(good.andThen((_) => err('later')).err()).toBe('later')
    expect(bad.andThen((n) => ok(n + 1)).err()).toBe('failed')
    expect(good.or(ok(9)).unwrap()).toBe(2)
    expect(bad.or(ok(9)).unwrap()).toBe(9)
    expect(good.orElse(() => ok(9)).unwrap()).toBe(2)
    expect(bad.orElse((e) => ok(e.length)).unwrap()).toBe(6)
  })

  it('unwraps with a fallback', () => {
    expect(good.unwrapOr(0)).toBe(2)
    expect(bad.unwrapOr(null)).toBeNull()
    expect(good.unwrapOrElse(() => 0)).toBe(2)
    expect(bad.unwrapOrElse((e) => e.length)).toBe(6)
  })

  it('throws from unwrap and expect only, with the error as the cause', () => {
    expect(good.unwrap()).toBe(2)
    expect(good.expect('needed')).toBe(2)
    let thrown: unknown
    try {
      bad.unwrap()
    } catch (error) {
      thrown = error
    }
    expect(thrown).toBeInstanceOf(Error)
    expect((thrown as Error).cause).toBe('failed')
    expect(() => bad.expect('needed a number')).toThrow(
      'needed a number: failed',
    )
  })

  it('is frozen', () => {
    expect(Object.isFrozen(good)).toBe(true)
    expect(Object.isFrozen(bad)).toBe(true)
  })
})
