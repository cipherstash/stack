/**
 * Behavioural tests for the v3 wire format: plain JSONB, never the v2
 * `eql_v2_encrypted` composite literal. v3 columns are
 * `CREATE DOMAIN public.eql_v3_* AS jsonb ...`, so the wire is JSON
 * text on the way in and JSON text (or a driver-pre-parsed object) on
 * the way out.
 */

import { describe, expect, it } from 'vitest'
import { v3FromDriver, v3ToDriver } from '../../src/v3/wire-v3'

describe('v3 wire (plain JSONB)', () => {
  it('serialises to JSON text, never the v2 composite literal', () => {
    expect(v3ToDriver({ a: 1 })).toBe('{"a":1}')
    expect(v3ToDriver({ a: 1 })).not.toMatch(/^\(/)
  })

  it('null/undefined -> null', () => {
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })

  it('bigintSafeReplacer: a stray bigint in a malformed envelope serialises to its decimal string, not a throw', () => {
    // A well-formed envelope never carries a bigint (bigint plaintext is
    // encrypted to ciphertext strings first); this pins the defensive
    // guard so the codec never throws "Do not know how to serialize a BigInt".
    expect(v3ToDriver({ c: 10n })).toBe('{"c":"10"}')
    expect(() => v3ToDriver({ c: 9007199254740993n })).not.toThrow()
    expect(v3ToDriver({ c: 9007199254740993n })).toBe(
      '{"c":"9007199254740993"}',
    )
  })

  it('fromDriver parses text, passes objects through, preserves null/undefined', () => {
    expect(v3FromDriver('{"a":1}')).toEqual({ a: 1 })
    expect(v3FromDriver({ a: 1 } as object)).toEqual({ a: 1 })
    expect(v3FromDriver(null)).toBeNull()
    expect(v3FromDriver(undefined)).toBeUndefined()
  })

  it('fromDriver(toDriver(payload)) round-trips an EQL payload', () => {
    const payload = { c: 'abc', i: { t: 'users', c: 'email' }, v: 2 }
    expect(v3FromDriver(v3ToDriver(payload))).toEqual(payload)
  })
})
