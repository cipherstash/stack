import { describe, expect, it } from 'vitest'
import { RecipherError } from '../../src/error'

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

  it('keeps the help, URL, fields and causes the addon gives it', () => {
    // The addon calls the constructor with the error's fields.
    const error = new RecipherError({
      code: 'stack_kms::x',
      message: 'refused',
      help: 'try again',
      url: 'https://example.com/x',
      severity: 'warning',
      fields: { request_kind: 'generate', status: 503 },
      causes: [
        { code: 'stack_kms::y', message: 'inner' },
        { message: 'an error from another library' },
      ],
      field: 'email',
    })
    expect(error.help).toBe('try again')
    expect(error.url).toBe('https://example.com/x')
    expect(error.severity).toBe('warning')
    expect(error.fields).toEqual({ request_kind: 'generate', status: 503 })
    expect(error.causes).toEqual([
      { code: 'stack_kms::y', message: 'inner' },
      { message: 'an error from another library' },
    ])
    expect(error.field).toBe('email')
    expect(Object.isFrozen(error.fields)).toBe(true)
    expect(Object.isFrozen(error.causes)).toBe(true)
  })

  it('defaults what the addon leaves out', () => {
    const error = new RecipherError({ code: 'stack_kms::x', message: 'm' })
    expect(error.help).toBeUndefined()
    expect(error.url).toBeUndefined()
    expect(error.severity).toBe('error')
    expect(error.fields).toEqual({})
    expect(error.causes).toEqual([])
    expect(error.field).toBeUndefined()
    expect(error.record).toBeUndefined()
  })
})
