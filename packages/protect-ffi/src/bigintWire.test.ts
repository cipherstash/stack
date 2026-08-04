import { describe, expect, it } from 'vitest'
import {
  BIGINT_MAX,
  BIGINT_MIN,
  BIGINT_WIRE_KEY,
  encodeBigIntPlaintext,
  withEncodedPlaintext,
  withEncodedPlaintexts,
} from './bigintWire.js'

describe('encodeBigIntPlaintext', () => {
  it('encodes a bigint into the tagged wire map with a decimal string', () => {
    expect(encodeBigIntPlaintext(42n)).toEqual({ [BIGINT_WIRE_KEY]: '42' })
    expect(encodeBigIntPlaintext(-1n)).toEqual({ [BIGINT_WIRE_KEY]: '-1' })
  })

  it('passes non-bigint plaintexts through untouched', () => {
    for (const value of ['abc', 42, 42.5, true, { a: 1 }, [1, 2]]) {
      expect(encodeBigIntPlaintext(value)).toBe(value)
    }
  })

  it('round-trips the i64 boundaries exactly', () => {
    expect(BIGINT_MAX).toBe(9223372036854775807n)
    expect(BIGINT_MIN).toBe(-9223372036854775808n)
    expect(encodeBigIntPlaintext(BIGINT_MAX)).toEqual({
      [BIGINT_WIRE_KEY]: '9223372036854775807',
    })
    expect(encodeBigIntPlaintext(BIGINT_MIN)).toEqual({
      [BIGINT_WIRE_KEY]: '-9223372036854775808',
    })
  })

  it('rejects 2^63 (just above i64::MAX) with a RangeError naming the bounds and direction', () => {
    expect(() => encodeBigIntPlaintext(BIGINT_MAX + 1n)).toThrowError(
      RangeError,
    )
    expect(() => encodeBigIntPlaintext(BIGINT_MAX + 1n)).toThrowError(
      /above the maximum.*-9223372036854775808 to 9223372036854775807/,
    )
  })

  it('rejects -(2^63) - 1 (just below i64::MIN) with a RangeError naming the bounds and direction', () => {
    expect(() => encodeBigIntPlaintext(BIGINT_MIN - 1n)).toThrowError(
      RangeError,
    )
    expect(() => encodeBigIntPlaintext(BIGINT_MIN - 1n)).toThrowError(
      /below the minimum.*-9223372036854775808 to 9223372036854775807/,
    )
  })

  it('does not echo the plaintext value in the error (it is a secret)', () => {
    const secret = BIGINT_MAX + 12345n
    try {
      encodeBigIntPlaintext(secret)
      expect.unreachable('must throw')
    } catch (err) {
      expect(String(err)).not.toContain(secret.toString())
    }
  })
})

describe('withEncodedPlaintext', () => {
  it('returns the same object when the plaintext is not a bigint', () => {
    const opts = { plaintext: 'abc', column: 'email', table: 'users' }
    expect(withEncodedPlaintext(opts)).toBe(opts)
  })

  it('clones and encodes when the plaintext is a bigint, leaving the input untouched', () => {
    const opts = { plaintext: 42n, column: 'score', table: 'users' }
    const encoded = withEncodedPlaintext(opts)
    expect(encoded).not.toBe(opts)
    expect(encoded.plaintext).toEqual({ [BIGINT_WIRE_KEY]: '42' })
    expect(encoded.column).toBe('score')
    expect(opts.plaintext).toBe(42n)
  })

  it('lets a null/undefined element fall through instead of throwing a raw TypeError', () => {
    // The deliberate `opts?.` optional chaining: a null/undefined element
    // must be returned as-is so it reaches native's own validation, rather
    // than throwing a property-access TypeError here.
    expect(() =>
      withEncodedPlaintext(null as unknown as { plaintext: unknown }),
    ).not.toThrow()
    expect(
      withEncodedPlaintext(null as unknown as { plaintext: unknown }),
    ).toBeNull()
    expect(
      withEncodedPlaintext(undefined as unknown as { plaintext: unknown }),
    ).toBeUndefined()
  })
})

describe('withEncodedPlaintexts', () => {
  it('returns the same array when no payload carries a bigint', () => {
    const payloads = [
      { plaintext: 'abc', column: 'email', table: 'users' },
      { plaintext: 42, column: 'score', table: 'users' },
    ]
    expect(withEncodedPlaintexts(payloads)).toBe(payloads)
  })

  it('encodes only the bigint payloads', () => {
    const payloads = [
      { plaintext: 'abc' as unknown, column: 'email', table: 'users' },
      { plaintext: 42n as unknown, column: 'score', table: 'users' },
    ]
    const encoded = withEncodedPlaintexts(payloads)
    expect(encoded).not.toBe(payloads)
    expect(encoded[0]).toBe(payloads[0])
    expect(encoded[1].plaintext).toEqual({ [BIGINT_WIRE_KEY]: '42' })
    expect(payloads[1].plaintext).toBe(42n)
  })

  it('propagates the RangeError for an out-of-range payload', () => {
    const payloads = [
      { plaintext: BIGINT_MAX + 1n, column: 'score', table: 'users' },
    ]
    expect(() => withEncodedPlaintexts(payloads)).toThrowError(RangeError)
  })

  it('lets null/undefined elements fall through even when a sibling carries a bigint', () => {
    // The decisive case the source comment calls out: a bad element's fate
    // must not depend on whether a *sibling* carries a bigint (which is what
    // triggers the `.map(withEncodedPlaintext)` encoding pass). null/undefined
    // must fall through to native validation, not throw a raw TypeError.
    const payloads = [
      null,
      { plaintext: 42n as unknown, column: 'score', table: 'users' },
      undefined,
    ] as unknown as { plaintext: unknown }[]

    expect(() => withEncodedPlaintexts(payloads)).not.toThrow()

    const encoded = withEncodedPlaintexts(payloads)
    expect(encoded[0]).toBeNull()
    expect(encoded[1].plaintext).toEqual({ [BIGINT_WIRE_KEY]: '42' })
    expect(encoded[2]).toBeUndefined()
  })
})
