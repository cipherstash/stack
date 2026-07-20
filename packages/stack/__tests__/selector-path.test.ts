import { describe, expect, it } from 'vitest'
import { unsupportedLeafReason } from '@/eql/v3/selector-path'

describe('unsupportedLeafReason', () => {
  it.each([
    'value',
    42,
    true,
  ])('accepts the JSON scalar %j for equality', (value) => {
    expect(unsupportedLeafReason(value, false)).toBeNull()
  })

  it.each([
    'value',
    42,
  ])('accepts the orderable JSON scalar %j for ordering', (value) => {
    expect(unsupportedLeafReason(value, true)).toBeNull()
  })

  it.each([
    ['null', null, /non-null scalar leaf/],
    ['undefined', undefined, /non-null scalar leaf/],
    ['object', { nested: true }, /got an object/],
    ['array', ['nested'], /got an array/],
    ['Date', new Date('2026-01-02T03:04:05Z'), /got a Date/],
    ['bigint', 10n, /got bigint/],
    ['NaN', Number.NaN, /only finite numbers/],
    ['Infinity', Number.POSITIVE_INFINITY, /only finite numbers/],
  ] as const)('rejects an unsupported %s leaf', (_label, value, reason) => {
    expect(unsupportedLeafReason(value, false)).toMatch(reason)
  })

  it('rejects boolean ordering while retaining boolean equality', () => {
    expect(unsupportedLeafReason(true, true)).toMatch(/no ordering/)
    expect(unsupportedLeafReason(true, false)).toBeNull()
  })
})
