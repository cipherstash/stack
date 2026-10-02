// Shared helpers for Node module-resolution failures. A missing dependency
// surfaces as a `MODULE_NOT_FOUND` (CJS require) or `ERR_MODULE_NOT_FOUND` (ESM
// import) whose message names the unresolved specifier. These turn that raw
// error into structured data callers translate into guidance — missing native
// binaries in `native.ts`, missing CipherStash packages in
// `config/missing-package.ts`, and which of those a failed `stash doctor` probe
// hit in `commands/doctor`.

/** A Node module-resolution error. */
export interface ModuleError extends Error {
  code?: string
  requireStack?: string[]
}

/** True when `err` is a CJS `MODULE_NOT_FOUND` or ESM `ERR_MODULE_NOT_FOUND`. */
export function isModuleNotFound(err: unknown): err is ModuleError {
  if (!(err instanceof Error)) return false
  const code = (err as ModuleError).code
  return code === 'MODULE_NOT_FOUND' || code === 'ERR_MODULE_NOT_FOUND'
}

/**
 * The quoted specifier from a module-not-found message, or `undefined`. CJS says
 * "Cannot find module 'X'"; ESM says "Cannot find package 'X'". Handles subpath
 * specifiers too (e.g. `@cipherstash/stack/schema`).
 */
export function moduleNotFoundSpecifier(err: ModuleError): string | undefined {
  return /Cannot find (?:module|package) '([^']+)'/.exec(err.message)?.[1]
}

/**
 * True when `pkg` itself is what failed to resolve — it is not installed — as
 * opposed to installed and unable to load something.
 *
 * Matched on the SPECIFIER Node quotes, never on the message text. A substring
 * test for the package name is wrong in both directions: an import of
 * `@cipherstash/stack/diagnostics` that fails on a missing `dist/` file names
 * `…/node_modules/@cipherstash/stack/dist/diagnostics.js` — installed and
 * broken, reported as never installed — and `@cipherstash/stack-drizzle`
 * contains `@cipherstash/stack`.
 */
export function isPackageMissing(err: unknown, pkg: string): boolean {
  if (!isModuleNotFound(err)) return false
  const specifier = moduleNotFoundSpecifier(err)
  if (specifier === undefined) return false
  // For a subpath of an absent package Node quotes the base package under ESM
  // but the whole specifier under CJS. Both mean this package.
  return specifier === pkg || specifier.startsWith(`${pkg}/`)
}

/**
 * True when `target.pkg` is installed but does not publish `target.subpath` —
 * an `@cipherstash/stack` older than `./diagnostics`, say. False when the
 * caller asked for no subpath, since then there is none to be missing.
 *
 * Worth telling apart because it is not a broken install: `stash` declares
 * `@cipherstash/stack` as an optional peer with a wide range, so every version
 * inside that range predating a subpath lands here, and the user did nothing
 * wrong.
 *
 * Narrow on purpose, because the guidance that follows from it names a package
 * and a version. `ERR_PACKAGE_PATH_NOT_EXPORTED` alone does not carry that: an
 * exports failure can come from anywhere in an import graph, including a
 * dependency of a dependency. So the error must be about this subpath of this
 * package, or it is somebody else's problem and must not be answered with an
 * upgrade.
 */
export function isSubpathUnavailable(
  err: unknown,
  target: { pkg: string; subpath?: string },
): boolean {
  if (target.subpath === undefined) return false
  if (!(err instanceof Error)) return false
  if ((err as { code?: string }).code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') {
    return false
  }
  // Node names both halves: `Package subpath './diagnostics' is not defined by
  // "exports" in /…/@cipherstash/stack/package.json`. Separators normalised
  // because win32 is a supported target and that path is built by the OS.
  const message = err.message.replaceAll('\\', '/')
  return (
    message.includes(`'${target.subpath}'`) &&
    message.includes(`${target.pkg}/package.json`)
  )
}
