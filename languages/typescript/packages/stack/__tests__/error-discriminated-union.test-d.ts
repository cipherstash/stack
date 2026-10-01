import {
  type ClientInitError,
  type EncryptionError,
  EncryptionErrorTypes,
  type StackError,
} from '@cipherstash/stack/errors'
import { describe, expectTypeOf, it } from 'vitest'

/**
 * Regression guard for the `as const` on EncryptionErrorTypes: without it every
 * member's value widens to `string`, so the StackError `type` fields stop
 * discriminating and the documented exhaustive `switch (error.type)` — including
 * `error.code` access on the narrowed branch — fails to compile. This suite is
 * that documented pattern; if `as const` is dropped it goes red.
 */
describe('StackError discriminated union (errors as const)', () => {
  it('literal member types, not string', () => {
    expectTypeOf(
      EncryptionErrorTypes.EncryptionError,
    ).toEqualTypeOf<'EncryptionError'>()
    expectTypeOf<EncryptionError['type']>().toEqualTypeOf<
      | 'ClientInitError'
      | 'EncryptionError'
      | 'DecryptionError'
      | 'LockContextError'
      | 'CtsTokenError'
    >()
  })

  it('narrows on `type` and exhausts', () => {
    const handle = (error: StackError): string => {
      switch (error.type) {
        case EncryptionErrorTypes.ClientInitError: {
          expectTypeOf(error).toEqualTypeOf<ClientInitError>()
          return error.message
        }
        case EncryptionErrorTypes.EncryptionError:
        case EncryptionErrorTypes.DecryptionError:
          // `code` reaches these branches from protect-ffi — proves narrowing
          // works. (`ClientInitError` carries it too, for the same reason;
          // `LockContextError` and `CtsTokenError` do not, because neither
          // comes from protect-ffi.)
          return error.code ?? error.message
        case EncryptionErrorTypes.LockContextError:
          return error.message
        case EncryptionErrorTypes.CtsTokenError:
          // Narrowing here reaches `authCode`: `LockContext.identify()` calls
          // CTS over HTTP itself, so a billing refusal surfaces on this branch
          // rather than through protect-ffi.
          return error.authCode ?? error.message
        default: {
          const _exhaustive: never = error
          return _exhaustive
        }
      }
    }
    expectTypeOf(handle).toBeFunction()
  })
})
