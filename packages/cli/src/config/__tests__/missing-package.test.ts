import { describe, expect, it } from 'vitest'
import { missingCipherStashPackage } from '../missing-package.js'

function moduleErr(message: string, code = 'MODULE_NOT_FOUND'): Error {
  return Object.assign(new Error(message), { code })
}

describe('missingCipherStashPackage', () => {
  it('detects a missing bare `stash` (the config import)', () => {
    expect(
      missingCipherStashPackage(moduleErr("Cannot find module 'stash'")),
    ).toBe('stash')
  })

  it('detects a missing `@cipherstash/stack` (ESM "package" wording)', () => {
    expect(
      missingCipherStashPackage(
        moduleErr(
          "Cannot find package '@cipherstash/stack'",
          'ERR_MODULE_NOT_FOUND',
        ),
      ),
    ).toBe('@cipherstash/stack')
  })

  it('reduces a subpath specifier to its package name (#3)', () => {
    // The client imports subpaths like `@cipherstash/stack/schema`; the brittle
    // substring match this replaced missed those.
    expect(
      missingCipherStashPackage(
        moduleErr("Cannot find module '@cipherstash/stack/schema'"),
      ),
    ).toBe('@cipherstash/stack')
  })

  it('ignores a missing third-party package', () => {
    expect(
      missingCipherStashPackage(moduleErr("Cannot find module 'left-pad'")),
    ).toBeUndefined()
  })

  it('ignores errors that are not module-not-found', () => {
    expect(
      missingCipherStashPackage(
        moduleErr("Cannot find module 'stash'", 'EACCES'),
      ),
    ).toBeUndefined()
    expect(missingCipherStashPackage(new SyntaxError('boom'))).toBeUndefined()
  })

  it('ignores non-Error values', () => {
    expect(missingCipherStashPackage(undefined)).toBeUndefined()
    expect(missingCipherStashPackage('boom')).toBeUndefined()
  })
})
