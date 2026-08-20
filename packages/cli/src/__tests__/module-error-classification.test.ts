import { createRequire } from 'node:module'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { isPackageMissing, isSubpathUnavailable } from '../module-error.js'
import { isNativeBinaryMissing } from '../native.js'

// The `module-error.ts` classifiers `stash doctor` sorts a failed probe with.
// Each arm renders a different row and a different exit code, so a probe error
// landing in the wrong one is a wrong diagnosis, not a cosmetic slip — and the
// two here are the ones whose answers are indistinguishable to the user: a
// green "not installed", or advice to upgrade.
//
// Every fixture below is an error NODE raised, never one built by hand with the
// code and message pasted on. A hand-built fixture asserts on itself: it keeps
// passing when Node changes the shape the classifier has to recognise, which is
// exactly how `isNativeBinaryMissing` came to have a `@cipherstash/auth` arm
// that could never fire.
const require = createRequire(import.meta.url)

function resolutionError(specifier: string): unknown {
  try {
    require.resolve(specifier)
  } catch (err) {
    return err
  }
  throw new Error(`${specifier} resolved; it was expected to fail`)
}

// `stash` declares `@cipherstash/stack` as an OPTIONAL PEER at `>=1.0.0-rc.0`,
// and the encryption probe imports its `./diagnostics` subpath. So any install
// predating that subpath — a range the CLI itself permits — fails resolution
// with neither a missing package nor a missing binary. Without its own arm that
// error reaches doctor's `else` and is rethrown, surfacing as the launcher's
// bare `Fatal error` for an install that may be perfectly healthy.
describe('isSubpathUnavailable', () => {
  // The two probes as `doctor` declares them: one imports a subpath, one does
  // not.
  const encryption = { pkg: '@cipherstash/stack', subpath: './no-such-subpath' }
  const auth = { pkg: '@cipherstash/auth' }

  it('matches an installed package that does not publish the subpath', () => {
    // A real package (so resolution gets as far as reading its exports map)
    // with a subpath it has never had.
    const err = resolutionError('@cipherstash/stack/no-such-subpath')

    expect((err as { code?: string }).code).toBe(
      'ERR_PACKAGE_PATH_NOT_EXPORTED',
    )
    expect(isSubpathUnavailable(err, encryption)).toBe(true)
  })

  it('does not match a probe that imports no subpath', () => {
    // The advice this arm renders names `@cipherstash/stack` and tells the user
    // to upgrade it. Applied to the auth probe — which imports the package root
    // — any exports failure raised somewhere inside auth's own dependency graph
    // would answer a broken install with an unrelated upgrade and exit 0.
    const err = resolutionError('@cipherstash/stack/no-such-subpath')

    expect(isSubpathUnavailable(err, auth)).toBe(false)
  })

  it('does not match a failure on a different subpath of the same package', () => {
    // A dependency deeper in the probe's own import graph with an exports
    // problem of its own is not "your @cipherstash/stack is too old".
    const err = resolutionError('@cipherstash/stack/no-such-subpath')

    expect(
      isSubpathUnavailable(err, {
        pkg: '@cipherstash/stack',
        subpath: './diagnostics',
      }),
    ).toBe(false)
  })

  it('does not match the errors the other arms own', () => {
    // An absent package: Node names the BASE package here, which is why the
    // probe classifies against `@cipherstash/stack` while importing the
    // subpath, and why this must not be mistaken for a stale install.
    const missing = resolutionError('@cipherstash/no-such-package/diagnostics')
    expect((missing as { code?: string }).code).toBe('MODULE_NOT_FOUND')
    expect(isSubpathUnavailable(missing, encryption)).toBe(false)

    const binary = new Error(
      "Cannot find module '@cipherstash/protect-ffi-darwin-arm64'",
    ) as Error & { code?: string }
    binary.code = 'MODULE_NOT_FOUND'
    expect(isSubpathUnavailable(binary, encryption)).toBe(false)
    expect(isNativeBinaryMissing(binary)).toBe(true)
  })

  it('ignores non-Error values', () => {
    expect(isSubpathUnavailable(undefined, encryption)).toBe(false)
    expect(
      isSubpathUnavailable(
        { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' },
        encryption,
      ),
    ).toBe(false)
  })
})

// The arm that decides whether a probe failure means "you have not installed
// this yet" — a green row for the optional peer — or something the user has to
// act on. Getting a false positive here is the worst outcome doctor has: it
// tells a user with a broken install that there is nothing to fix.
describe('isPackageMissing', () => {
  it('matches the package the probe named', () => {
    const err = resolutionError('@cipherstash/no-such-package/diagnostics')

    expect(isPackageMissing(err, '@cipherstash/no-such-package')).toBe(true)
  })

  it('does not match a load failure for a file inside an installed package', () => {
    // The probe imports `@cipherstash/stack/diagnostics`, so its failures name
    // paths INSIDE the package — `…/node_modules/@cipherstash/stack/dist/
    // diagnostics.js`. A substring test for the package name matches that
    // happily and reports a package that is installed but broken (an
    // interrupted install, a partially built workspace) as one the user has
    // simply not installed yet: a green row, and no reason to look further.
    //
    // The path the CLI's own resolution produces — `packages/cli/node_modules/
    // @cipherstash/stack/…`, the workspace's stand-in for a user's install.
    // Not `require.resolve('@cipherstash/stack/package.json')`: that returns
    // the symlink's REAL path (`packages/stack/…`), which drops the scoped
    // name the bug turns on. Node raises the error either way; only the path
    // handed to it is composed here.
    //
    // Resolved through CJS to keep Node's own resolver in play rather than
    // Vitest's module pipeline. The ESM form of this message differs only by a
    // trailing `imported from …`, and both quote the same specifier.
    const cliRoot = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      '../..',
    )
    const err = resolutionError(
      path.join(
        cliRoot,
        'node_modules/@cipherstash/stack/dist/no-such-file.js',
      ),
    )

    expect((err as { code?: string }).code).toBe('MODULE_NOT_FOUND')
    expect((err as Error).message).toContain('@cipherstash/stack')
    expect(isPackageMissing(err, '@cipherstash/stack')).toBe(false)
  })

  it('does not match a sibling package that merely shares a prefix', () => {
    const err = resolutionError('@cipherstash/no-such-package-extra')

    expect(isPackageMissing(err, '@cipherstash/no-such-package')).toBe(false)
  })

  it('ignores errors that are not module resolution failures', () => {
    expect(
      isPackageMissing(new Error('@cipherstash/stack'), '@cipherstash/stack'),
    ).toBe(false)
    expect(isPackageMissing(undefined, '@cipherstash/stack')).toBe(false)
  })
})
