import { describe, expect, it } from 'vitest'
import { v3FromDriver, v3ToDriver } from '@/eql/v3/drizzle/codec'

describe('v3 codec', () => {
  it('serialises an object to a jsonb string', () => {
    expect(v3ToDriver({ v: 1, c: 'ct' })).toBe('{"v":1,"c":"ct"}')
  })

  it('maps null/undefined to SQL NULL (JS null), never the JSON null literal', () => {
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })

  it('parses a jsonb string back to an object', () => {
    expect(v3FromDriver('{"v":1,"c":"ct"}')).toEqual({ v: 1, c: 'ct' })
  })

  it('passes an already-parsed object through unchanged', () => {
    const obj = { v: 1 }
    expect(v3FromDriver(obj)).toBe(obj)
  })

  it('passes null/undefined through on read', () => {
    expect(v3FromDriver(null)).toBeNull()
    expect(v3FromDriver(undefined)).toBeUndefined()
  })
})
