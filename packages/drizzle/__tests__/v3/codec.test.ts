import { describe, expect, it } from 'vitest'
import { v3FromDriver, v3ToDriver } from '../../src/pg/v3/codec'

describe('v3 plain-jsonb codec', () => {
  it('toDriver serialises the payload as plain JSON (no composite wrapper)', () => {
    const payload = {
      v: '2',
      i: { t: 'users', c: 't_eq' },
      c: 'ct',
      hm: 'hmac',
    }
    const wire = v3ToDriver(payload)
    expect(wire).toBe(JSON.stringify(payload))
    // not v2's ("…") composite (typeof guard: v3ToDriver returns string | null)
    expect(typeof wire === 'string' && wire.startsWith('(')).toBe(false)
  })

  it('fromDriver round-trips a plain-jsonb object', () => {
    const payload = {
      v: '2',
      i: { t: 'users', c: 't_eq' },
      c: 'ct',
      hm: 'hmac',
    }
    expect(v3FromDriver(JSON.stringify(payload))).toEqual(payload)
  })

  it('fromDriver accepts an already-parsed object (postgres jsonb auto-parse)', () => {
    const payload = { v: '2', c: 'ct' }
    // No cast needed now: v3FromDriver's param is string | object | null.
    expect(v3FromDriver(payload)).toEqual(payload)
  })

  it('fromDriver maps NULL to null', () => {
    expect(v3FromDriver(null)).toBeNull()
  })

  it('fromDriver maps undefined (absent column) to undefined', () => {
    expect(v3FromDriver(undefined)).toBeUndefined()
  })

  it('fromDriver throws on malformed jsonb (surfaces the parse error)', () => {
    expect(() => v3FromDriver('{not valid json')).toThrow()
  })

  it('toDriver maps null/undefined to SQL NULL (JS null), not the JSONB null literal', () => {
    // Returning 'null' would bind JSONB null and fail the v3 domain CHECK
    // (jsonb_typeof = 'object'); JS null binds SQL NULL, which the domain accepts.
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })
})
