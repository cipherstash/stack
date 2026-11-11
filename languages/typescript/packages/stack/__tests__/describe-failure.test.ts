import { PROTECT_ERROR_CODES } from '@cipherstash/protect-ffi'
import { describe, expect, it } from 'vitest'
import {
  describeFailure,
  FFI_ERROR_CODES,
} from '@/utils/logger/describe-failure'

// `describeFailure` is what adapters log in place of an error's message, which
// may quote a plaintext value (CIP-5161). Everything it returns must come from
// a fixed allowlist, never from the error, however identifier-like the error's
// fields look.
describe('describeFailure', () => {
  it('names an Error by its class, never its message', () => {
    expect(describeFailure(new TypeError('value "Qzx" is bad'))).toBe(
      'TypeError',
    )
  })

  it('appends known type, code and authCode identifiers', () => {
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

  // An identifier-shaped field can still hold caller data, so the shape is not
  // the test: only known values pass.
  it('drops identifier-shaped values that are not known codes', () => {
    const err = Object.assign(new Error('invalid value'), {
      code: 'Qzx-secret-wvy',
      type: 'alice.smith',
      authCode: '123-45-6789',
    })
    expect(describeFailure(err)).toBe('Error')
    expect(describeFailure({ code: 'Qzx_secret', message: 'x' })).toBe('object')
    expect(describeFailure({ code: 42883 })).toBe('object')
  })

  it('reports an unknown error class as Error', () => {
    const renamed = new Error('x')
    renamed.name = 'QzxSecret'
    expect(describeFailure(renamed)).toBe('Error')
  })

  it('describes a non-object by its type', () => {
    expect(describeFailure('Qzx')).toBe('string')
    expect(describeFailure(null)).toBe('null')
    expect(describeFailure(undefined)).toBe('undefined')
  })

  // Called from inside a catch: if describing the failure threw, Supabase would
  // reject instead of returning `{ error }`, and DynamoDB would skip its
  // errorHandler.
  it('returns a fixed description when reading the error throws', () => {
    const err = new Error('x')
    Object.defineProperty(err, 'type', {
      get() {
        throw new Error('getter Qzx')
      },
    })
    expect(describeFailure(err)).toBe('unknown failure')

    const { proxy, revoke } = Proxy.revocable({}, {})
    revoke()
    expect(describeFailure(proxy)).toBe('unknown failure')
  })

  it('allowlists exactly the FFI error codes protect-ffi declares', () => {
    expect([...FFI_ERROR_CODES].sort()).toEqual([...PROTECT_ERROR_CODES].sort())
  })
})
