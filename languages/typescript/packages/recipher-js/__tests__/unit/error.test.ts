import { describe, expect, it } from 'vitest'
import { fromNative, RecipherError } from '../../src/error'

describe('RecipherError', () => {
  it('is frozen and prints its code and message', () => {
    const error = new RecipherError({
      code: 'stack_encrypt::aead',
      message: 'did not open',
    })
    expect(Object.isFrozen(error)).toBe(true)
    expect(String(error)).toBe(
      'RecipherError(stack_encrypt::aead): did not open',
    )
  })

  it('prints its help on a line of its own', () => {
    const error = new RecipherError({
      code: 'stack_encrypt::aead',
      message: 'did not open',
      help: 'check the context',
    })
    expect(error.message).toBe('did not open')
    expect(String(error)).toBe(
      'RecipherError(stack_encrypt::aead): did not open\nhelp: check the context',
    )
  })

  it('keeps the help, URL, fields and causes of a native error', () => {
    const read = fromNative({
      code: 'stack_kms::x',
      message: 'refused',
      help: 'try again',
      url: 'https://example.com/x',
      severity: 'warning',
      fields: { request_kind: 'generate', status: 503 },
      causes: [
        { code: 'stack_kms::y', message: 'inner' },
        { message: 'an error from another library' },
        'not a cause',
      ],
    })
    expect(read.help).toBe('try again')
    expect(read.url).toBe('https://example.com/x')
    expect(read.severity).toBe('warning')
    expect(read.fields).toEqual({ request_kind: 'generate', status: 503 })
    expect(read.causes).toEqual([
      { code: 'stack_kms::y', message: 'inner' },
      { message: 'an error from another library' },
    ])
    expect(Object.isFrozen(read.fields)).toBe(true)
    expect(Object.isFrozen(read.causes)).toBe(true)
  })

  it('reads a native error, and refuses one of an unknown shape', () => {
    const read = fromNative({
      code: 'stack_kms::x',
      message: 'refused',
      help: null,
      field: 'email',
    })
    expect(read.code).toBe('stack_kms::x')
    expect(read.message).toBe('refused')
    expect(read.field).toBe('email')
    expect(read.help).toBeUndefined()
    // An error that states no severity, or an unknown one, is an error.
    expect(read.severity).toBe('error')
    expect(
      fromNative({ code: 'c', message: 'm', severity: 'loud' }).severity,
    ).toBe('error')
    expect(read.fields).toEqual({})
    expect(read.causes).toEqual([])

    // An error with no code or no message is not one the native build
    // writes.
    for (const shape of [{ message: 'm' }, { code: 'c' }, null, 'text']) {
      expect(fromNative(shape).code).toBe('recipher_js::outcome')
    }
  })
})
