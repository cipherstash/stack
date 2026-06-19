import { describe, expect, it } from 'vitest'
import { isNativeBinaryMissing } from '../native.js'

interface ModuleError extends Error {
  code?: string
  requireStack?: string[]
}

function moduleError(
  message: string,
  requireStack: string[] = [],
): ModuleError {
  const err = new Error(message) as ModuleError
  err.code = 'MODULE_NOT_FOUND'
  err.requireStack = requireStack
  return err
}

describe('isNativeBinaryMissing', () => {
  it('matches a missing platform-specific protect-ffi binary', () => {
    // The real-world failure: npm skipped the optional native dependency.
    const err = moduleError(
      "Cannot find module '@cipherstash/protect-ffi-darwin-arm64'",
      [
        '/x/node_modules/@cipherstash/protect-ffi/lib/load.cjs',
        '/x/node_modules/@cipherstash/protect-ffi/lib/index.cjs',
      ],
    )
    expect(isNativeBinaryMissing(err)).toBe(true)
  })

  it('matches the auth native binary on linux/windows targets', () => {
    expect(
      isNativeBinaryMissing(
        moduleError("Cannot find module '@cipherstash/auth-linux-x64-gnu'"),
      ),
    ).toBe(true)
    expect(
      isNativeBinaryMissing(
        moduleError("Cannot find module '@cipherstash/auth-win32-x64-msvc'"),
      ),
    ).toBe(true)
  })

  it('matches when only the neon loader appears in the require stack', () => {
    const err = moduleError('Cannot find module somewhere', [
      '/x/node_modules/@neon-rs/load/dist/index.js',
    ])
    expect(isNativeBinaryMissing(err)).toBe(true)
  })

  it('does not match a missing top-level package', () => {
    expect(
      isNativeBinaryMissing(
        moduleError("Cannot find module '@cipherstash/stack'"),
      ),
    ).toBe(false)
  })

  it('does not match unrelated module errors', () => {
    expect(
      isNativeBinaryMissing(moduleError("Cannot find module 'left-pad'")),
    ).toBe(false)
  })

  it('does not match errors without a module-not-found code', () => {
    const err = new Error(
      'Cannot find module @cipherstash/protect-ffi-darwin-arm64',
    ) as ModuleError
    err.code = 'EACCES'
    expect(isNativeBinaryMissing(err)).toBe(false)
  })

  it('ignores non-Error values', () => {
    expect(isNativeBinaryMissing(undefined)).toBe(false)
    expect(isNativeBinaryMissing('boom')).toBe(false)
  })
})
