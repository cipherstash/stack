// Shared helpers for Node module-resolution failures. A missing dependency
// surfaces as a `MODULE_NOT_FOUND` (CJS require) or `ERR_MODULE_NOT_FOUND` (ESM
// import) whose message names the unresolved specifier. These turn that raw
// error into structured data callers translate into guidance — missing native
// binaries in `native.ts`, missing CipherStash packages in
// `config/missing-package.ts`.

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
