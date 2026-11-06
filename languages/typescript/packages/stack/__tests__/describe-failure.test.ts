import { describe, expect, it } from 'vitest'
import { describeFailure } from '@/utils/logger/describe-failure'

// `describeFailure` is what adapters log in place of an error's message, which
// may quote a plaintext value (CIP-5161). It must name the failure's kind and
// fixed identifiers, and nothing a caller supplied.
describe('describeFailure', () => {
  it('names an Error by its class, never its message', () => {
    const out = describeFailure(new TypeError('value "Qzx" is bad'))
    expect(out).toBe('TypeError')
  })

  it('appends the type, code and authCode identifiers', () => {
    const err = Object.assign(new Error('boom Qzx'), {
      type: 'EncryptionError',
      code: 'UNKNOWN_COLUMN',
      authCode: 'USAGE_LIMIT_EXCEEDED',
    })
    expect(describeFailure(err)).toBe(
      'Error: EncryptionError: UNKNOWN_COLUMN: USAGE_LIMIT_EXCEEDED',
    )
  })

  it('reads identifiers from a nested encryptionError', () => {
    const err = Object.assign(new Error('Qzx'), {
      name: 'EncryptionFailedError',
      encryptionError: {
        type: 'EncryptionError',
        message: 'Qzx',
        authCode: 'USAGE_LIMIT_EXCEEDED',
      },
    })
    expect(describeFailure(err)).toBe(
      'EncryptionFailedError: EncryptionError: USAGE_LIMIT_EXCEEDED',
    )
  })

  it('keeps the code of a non-Error failure, such as a PostgREST error object', () => {
    expect(describeFailure({ code: '42883', message: 'Qzx' })).toBe(
      'object: 42883',
    )
    expect(describeFailure({ code: 503 })).toBe('object: 503')
  })

  it('drops an identifier field that carries data instead of an identifier', () => {
    const err = Object.assign(new Error('x'), {
      code: 'value "Qzx" is not allowed',
      type: 'a'.repeat(65),
    })
    expect(describeFailure(err)).toBe('Error')
    const renamed = new Error('x')
    renamed.name = 'Qzx secret'
    expect(describeFailure(renamed)).toBe('Error')
  })

  it('describes a non-object by its type', () => {
    expect(describeFailure('Qzx')).toBe('string')
    expect(describeFailure(null)).toBe('null')
    expect(describeFailure(undefined)).toBe('undefined')
  })
})
