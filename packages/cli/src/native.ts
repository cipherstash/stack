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
import {
  detectPackageManager,
  type PackageManager,
  runnerCommand,
} from './commands/init/utils.js'

interface ModuleError extends Error {
  code?: string
  requireStack?: string[]
}

// Matches the platform-suffixed optional package, e.g.
// `@cipherstash/protect-ffi-darwin-arm64` or `@cipherstash/auth-linux-x64-gnu`.
const PLATFORM_PKG = /@cipherstash\/[a-z0-9-]+-(?:darwin|linux|win32)-[a-z0-9-]+/i

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
  return PLATFORM_PKG.test(haystack) || /[\\/]@neon-rs[\\/]load[\\/]/.test(haystack)
}

function missingModuleName(err: ModuleError): string | undefined {
  const haystack = `${err.message}\n${(err.requireStack ?? []).join('\n')}`
  // Prefer the real platform package name wherever it appears — on Linux it
  // carries a libc/toolchain suffix (e.g. `-linux-x64-gnu`) that a generic
  // `<platform>-<arch>` guess would miss.
  const pkg = PLATFORM_PKG.exec(haystack)?.[0]
  if (pkg) return pkg
  // Fall back to the quoted name. CJS says "Cannot find module 'X'"; ESM
  // (ERR_MODULE_NOT_FOUND) says "Cannot find package 'X'".
  return /Cannot find (?:module|package) '([^']+)'/.exec(err.message)?.[1]
}

// Recovery command to reinstall a project's dependencies from scratch.
function reinstallCommand(pm: PackageManager): string {
  switch (pm) {
    case 'bun':
      return 'rm -rf node_modules bun.lock && bun install'
    case 'pnpm':
      return 'rm -rf node_modules pnpm-lock.yaml && pnpm install'
    case 'yarn':
      return 'rm -rf node_modules yarn.lock && yarn install'
    case 'npm':
      return 'rm -rf node_modules package-lock.json && npm install'
  }
}

/**
 * Print actionable guidance for a missing native binary. Does not exit — the
 * caller decides the exit code so this can be reused by `stash doctor`.
 */
export function reportNativeBinaryMissing(err: unknown): void {
  const e = err instanceof Error ? (err as ModuleError) : undefined
  const missing = e ? missingModuleName(e) : undefined
  const target = currentTarget()
  const pm = detectPackageManager()
  // Runner-aware so we don't hardcode `npx` (see scripts/lint-no-hardcoded-runners.mjs):
  // npm → `npx`, bun → `bunx`, pnpm/yarn → `… dlx`.
  const rerun = `${runnerCommand(pm, 'stash@latest')} <command>`
  // The one-shot runner cache is npm-specific (`_npx`); for other package
  // managers a clean re-run is the equivalent first step.
  const rerunStep =
    pm === 'npm'
      ? `  rm -rf "$(npm config get cache)/_npx" && ${rerun}`
      : `  ${rerun}`

  p.log.error("stash couldn't load its native module for this platform.")
  p.note(
    [
      missing
        ? `Missing package: ${missing}`
        : `No native binary was loaded for ${target}.`,
      `Platform:        ${target}`,
      '',
      'stash ships prebuilt binaries as optional packages. Package managers',
      'sometimes skip them — a known npm bug: https://github.com/npm/cli/issues/4828',
      '',
      'Fix it with one of:',
      '',
      '  # re-run, clearing a stale runner cache',
      rerunStep,
      '',
      '  # if stash is a project dependency, reinstall',
      `  ${reinstallCommand(pm)}`,
      '',
      'Then run `stash doctor` to confirm.',
    ].join('\n'),
    'Native module not found',
  )
}
