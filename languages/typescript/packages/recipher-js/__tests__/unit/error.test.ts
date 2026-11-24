import { describe, expect, it } from 'vitest'
import { fromNative, RecipherError } from '../../src/error'

describe('RecipherError', () => {
  it('is frozen and prints its kind, code and message', () => {
    const error = new RecipherError({
      kind: 'open',
      code: 'stack_encrypt::aead',
      message: 'did not open',
    })
    expect(Object.isFrozen(error)).toBe(true)
    expect(String(error)).toBe(
      'RecipherError(open, stack_encrypt::aead): did not open',
    )
  })

  it('reads a native error, and refuses one of an unknown kind or shape', () => {
    const read = fromNative({
      kind: 'zerokms',
      code: 'stack_kms::x',
      message: 'refused',
      reason: null,
      field: 'email',
    })
    expect(read.kind).toBe('zerokms')
    expect(read.field).toBe('email')
    expect(read.reason).toBeUndefined()

    expect(fromNative({ kind: 'surprise' }).kind).toBe('internal')
    expect(fromNative(null).kind).toBe('internal')
    expect(fromNative('text').kind).toBe('internal')
  })
})
