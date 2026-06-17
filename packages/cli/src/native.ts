// Guards for the prebuilt native addons stash depends on.
//
// stash loads native Rust addons (e.g. @cipherstash/protect-ffi via
// @cipherstash/stack, and @cipherstash/auth) that are distributed as
// per-platform optional npm packages named `<pkg>-<platform>-<arch>` and
// selected at runtime by @neon-rs/load. npm intermittently skips installing
// these optional dependencies (https://github.com/npm/cli/issues/4828),
// leaving the base package present but the platform binary missing. The raw
// failure is an unhelpful MODULE_NOT_FOUND stack trace; these helpers detect
// that case and turn it into actionable guidance.

import * as p from '@clack/prompts'

interface ModuleError extends Error {
  code?: string
  requireStack?: string[]
}

/** `<platform>-<arch>` for the current process, e.g. `darwin-arm64`. */
export function currentTarget(): string {
  return `${process.platform}-${process.arch}`
}

/**
 * True when `err` is a failure to load one of our prebuilt native addons (a
 * missing `@cipherstash/<pkg>-<platform>-<arch>` optional package), as opposed
 * to a missing top-level package or any other module error.
 */
export function isNativeBinaryMissing(err: unknown): err is ModuleError {
  if (!(err instanceof Error)) return false
  const e = err as ModuleError
  // CJS require throws `MODULE_NOT_FOUND`; ESM throws `ERR_MODULE_NOT_FOUND`.
  if (e.code !== 'MODULE_NOT_FOUND' && e.code !== 'ERR_MODULE_NOT_FOUND') {
    return false
  }
  const haystack = `${e.message}\n${(e.requireStack ?? []).join('\n')}`
  // A platform-suffixed @cipherstash package, or a failure surfaced from the
  // neon loader, both mean the optional native binary wasn't installed.
  return (
    /@cipherstash\/[a-z0-9-]+-(?:darwin|linux|win32)-[a-z0-9-]+/i.test(
      haystack,
    ) || /[\\/]@neon-rs[\\/]load[\\/]/.test(haystack)
  )
}

function missingModuleName(err: ModuleError): string | undefined {
  return /Cannot find module '([^']+)'/.exec(err.message)?.[1]
}

/**
 * Print actionable guidance for a missing native binary. Does not exit — the
 * caller decides the exit code so this can be reused by `stash doctor`.
 */
export function reportNativeBinaryMissing(err: unknown): void {
  const e = err instanceof Error ? (err as ModuleError) : undefined
  const missing = e ? missingModuleName(e) : undefined
  const target = currentTarget()

  p.log.error("stash couldn't load its native module for this platform.")
  p.note(
    [
      missing
        ? `Missing package: ${missing}`
        : `Missing the @cipherstash/*-${target} native binary.`,
      `Platform:        ${target}`,
      '',
      'stash ships prebuilt binaries as optional npm packages. npm sometimes',
      'skips them due to a known bug (https://github.com/npm/cli/issues/4828).',
      '',
      'Fix it with one of:',
      '',
      '  # ran via npx',
      '  rm -rf "$(npm config get cache)/_npx" && npx stash@latest <command>',
      '',
      '  # stash is a project dependency',
      '  rm -rf node_modules package-lock.json && npm install',
      '',
      '  # installed globally',
      '  npm install -g stash@latest --force',
      '',
      'Then run `stash doctor` to confirm.',
    ].join('\n'),
    'Native module not found',
  )
}
