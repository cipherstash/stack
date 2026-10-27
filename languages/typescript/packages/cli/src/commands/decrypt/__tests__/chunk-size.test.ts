/**
 * `decrypt backfill --chunk-size`: what counts as a chunk size. The upper
 * bound is the one that matters most here: each row binds two parameters in
 * the chunk's write, and Postgres caps a statement at 65535, so a larger
 * chunk would fail only after its ZeroKMS request.
 */

import { MAX_DECRYPT_CHUNK_SIZE } from '@cipherstash/migrate'
import { describe, expect, it } from 'vitest'
import {
  InvalidDecryptChunkSizeError,
  parseDecryptChunkSize,
} from '../lib/chunk-size.js'

describe('parseDecryptChunkSize', () => {
  it('caps at 32767 rows, two bound parameters each', () => {
    expect(MAX_DECRYPT_CHUNK_SIZE).toBe(32767)
    expect(MAX_DECRYPT_CHUNK_SIZE * 2).toBeLessThanOrEqual(65535)
  })

  it.each([
    ['500', 500],
    ['1', 1],
    [' 42 ', 42],
    ['32767', 32767],
  ])('accepts %j as %d', (input, expected) => {
    expect(parseDecryptChunkSize(input)).toBe(expected)
  })

  it.each(['abc', '', '0', '-5', '1.5', '1e3', '0x10', 'Infinity', '32768'])(
    'rejects the text %j',
    (input) => {
      expect(() => parseDecryptChunkSize(input)).toThrow(
        InvalidDecryptChunkSizeError,
      )
    },
  )

  it('quotes what was typed and says why there is a ceiling', () => {
    expect(() => parseDecryptChunkSize('1e3')).toThrow(
      '--chunk-size must be a whole number of rows from 1 to 32767 (got "1e3").',
    )
    expect(() => parseDecryptChunkSize('32768')).toThrow(
      'from 1 to 32767 (got "32768"). Each row binds two parameters in the write, and Postgres allows 65535 per statement.',
    )
  })
})
