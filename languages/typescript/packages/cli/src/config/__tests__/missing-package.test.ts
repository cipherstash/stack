import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  missingCipherStashPackage,
  reportMissingCipherStashPackage,
} from '../missing-package.js'

// Pin map fixture so the guidance path is testable in source mode (where the
// build-time embed is absent). Versions are deliberately unreal.
vi.mock('../../runtime-versions.js', () => ({
  RUNTIME_PACKAGE_VERSIONS: { stash: '9.9.9-test.1' },
  expectedVersion: (pkg: string) =>
    ({ stash: '9.9.9-test.1', '@cipherstash/stack': '9.9.9-test.1' })[pkg],
  pinnedSpec: (pkg: string) => {
    const v = { stash: '9.9.9-test.1', '@cipherstash/stack': '9.9.9-test.1' }[
      pkg
    ]
    return v ? `${pkg}@${v}` : pkg
  },
}))

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

describe('reportMissingCipherStashPackage', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('prints PINNED install commands and exits 1 (#661)', () => {
    const errSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((() => {
      throw new Error('exit')
    }) as never)

    expect(() => reportMissingCipherStashPackage('stash')).toThrow('exit')

    expect(exitSpy).toHaveBeenCalledWith(1)
    const message = errSpy.mock.calls.map((c) => c.join(' ')).join('\n')
    // The guidance must name exact versions — a bare package name resolves
    // dist-tags, which is the #661 failure mode this guidance exists to avoid.
    expect(message).toContain('@cipherstash/stack@9.9.9-test.1')
    expect(message).toContain('stash@9.9.9-test.1')
  })
})
