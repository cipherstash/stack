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

  it('prints its help on a line of its own', () => {
    const error = new RecipherError({
      kind: 'open',
      code: 'stack_encrypt::aead',
      message: 'did not open',
      help: 'check the context',
    })
    expect(error.message).toBe('did not open')
    expect(String(error)).toBe(
      'RecipherError(open, stack_encrypt::aead): did not open\nhelp: check the context',
    )
  })

  it('keeps the help, URL, fields and causes of a native error', () => {
    const read = fromNative({
      kind: 'zerokms',
      code: 'stack_kms::x',
      message: 'refused',
      help: 'try again',
      url: 'https://example.com/x',
      fields: { request_kind: 'generate', status: 503 },
      causes: [
        { code: 'stack_kms::y', message: 'inner' },
        { message: 'an error from another library' },
        'not a cause',
      ],
    })
    expect(read.help).toBe('try again')
    expect(read.url).toBe('https://example.com/x')
    expect(read.fields).toEqual({ request_kind: 'generate', status: 503 })
    expect(read.causes).toEqual([
      { code: 'stack_kms::y', message: 'inner' },
      { message: 'an error from another library' },
    ])
    expect(Object.isFrozen(read.fields)).toBe(true)
    expect(Object.isFrozen(read.causes)).toBe(true)
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
    expect(read.help).toBeUndefined()
    expect(read.fields).toEqual({})
    expect(read.causes).toEqual([])

    expect(fromNative({ kind: 'surprise' }).kind).toBe('internal')
    expect(fromNative(null).kind).toBe('internal')
    expect(fromNative('text').kind).toBe('internal')
  })
})
