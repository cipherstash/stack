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

/**
 * What napi-rs's generated loader throws when the platform package is absent —
 * `@cipherstash/auth`'s shape. Verbatim from `stack-auth-node.js`, whose
 * `loadBinding()` swallows each candidate's resolver error (`try { … } catch
 * (_) {}`) and ends with this, so no `code` and no `requireStack` survive.
 */
function napiLoadError(pkg: string): Error {
  return new Error(
    `Failed to load native binding for ${process.platform}-${process.arch}. ` +
      `Ensure the optional dependency "${pkg}" is installed, ` +
      'or run "napi build" for local development.',
  )
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

  it('matches the auth native binary across targets', () => {
    // Auth is napi-rs, so these are the shape below, not `moduleError` — kept
    // as a set because the platform token varies (`-gnu`, `-msvc`, plain).
    for (const pkg of [
      '@cipherstash/auth-linux-x64-gnu',
      '@cipherstash/auth-win32-x64-msvc',
      '@cipherstash/auth-darwin-arm64',
    ]) {
      expect(isNativeBinaryMissing(napiLoadError(pkg)), pkg).toBe(true)
    }
  })

  it('matches the napi loader failure, which carries no code at all', () => {
    // The shape that made this whole helper a no-op for `@cipherstash/auth`.
    // Its loader requires each candidate inside `try { … } catch (_) {}` and
    // throws its own summary, so the resolver's MODULE_NOT_FOUND never
    // escapes: no `code`, no `requireStack`, only the message. This assertion
    // existed before as a hand-built error carrying `code =
    // 'MODULE_NOT_FOUND'` — a shape `@cipherstash/auth` has never thrown, so
    // it passed over a path that could not work, and `stash doctor` printed a
    // bare `Fatal error` for a missing auth binary instead of the guidance.
    const err = napiLoadError('@cipherstash/auth-darwin-arm64')
    expect((err as ModuleError).code).toBeUndefined()
    expect(isNativeBinaryMissing(err)).toBe(true)
  })

  it('does not match a napi loader failure from someone else', () => {
    // Both halves of the message test have to hold: the platform package is
    // what makes it ours.
    expect(
      isNativeBinaryMissing(napiLoadError('@other/thing-darwin-arm64')),
    ).toBe(false)
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
