/**
 * `--chunk-size` is the one backfill flag whose bad values do not fail at the
 * prompt: `Number('abc')` is `NaN`, and the engine binds whatever it is given
 * straight into `LIMIT $n`. These tests pin the single decision — what counts
 * as a chunk size — that both `encrypt backfill` and `decrypt backfill` defer
 * to, in both the forms it is reached with: raw argv text and a coerced
 * number.
 */

import { describe, expect, it } from 'vitest'
import {
  InvalidChunkSizeError,
  parseChunkSize,
  resolveChunkSize,
} from '../chunk-size.js'

describe('parseChunkSize', () => {
  it.each([
    ['500', 500],
    ['1', 1],
    [' 42 ', 42],
    ['007', 7],
    [500, 500],
    [1, 1],
  ])('accepts %j as %d', (input, expected) => {
    expect(parseChunkSize(input)).toBe(expected)
  })

  it.each([
    'abc',
    '',
    '   ',
    '0',
    '-5',
    '1.5',
    '1e3',
    '0x10',
    'Infinity',
    'NaN',
    '12abc',
  ])('rejects the text %j', (input) => {
    expect(() => parseChunkSize(input)).toThrow(InvalidChunkSizeError)
  })

  it.each([
    Number('abc'),
    0,
    -5,
    1.5,
    Number.POSITIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])('rejects the number %s', (input) => {
    expect(() => parseChunkSize(input)).toThrow(InvalidChunkSizeError)
  })

  it('names the flag and quotes exactly what was typed', () => {
    expect(() => parseChunkSize('abc')).toThrow(
      '--chunk-size must be a positive whole number of rows (got "abc").',
    )
  })

  it('reports a coerced number as the number it became', () => {
    // What a handler sees after argv's `Number(...)` — the raw text is gone,
    // so the message says what arrived rather than inventing a spelling.
    expect(() => parseChunkSize(Number('abc'))).toThrow('(got NaN)')
    expect(() => parseChunkSize(0)).toThrow('(got 0)')
    expect(() => parseChunkSize(1.5)).toThrow('(got 1.5)')
  })
})

describe('resolveChunkSize', () => {
  it('applies the fallback only when the flag was not given', () => {
    expect(resolveChunkSize(undefined, 1000)).toBe(1000)
    expect(resolveChunkSize(250, 1000)).toBe(250)
    expect(resolveChunkSize('250', 1000)).toBe(250)
  })

  it('does not let a bad value fall back to the default', () => {
    // A typo must be an error, not a silent 1000-row run.
    expect(() => resolveChunkSize(Number('abc'), 1000)).toThrow(
      InvalidChunkSizeError,
    )
    expect(() => resolveChunkSize('', 1000)).toThrow(InvalidChunkSizeError)
    expect(() => resolveChunkSize(0, 1000)).toThrow(InvalidChunkSizeError)
  })
})
