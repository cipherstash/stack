import { isEncrypted } from '@cipherstash/protect-ffi'

/**
 * Install diagnostics. One export, and it exists so `stash doctor` can prove
 * the native binding is present.
 *
 * **Why a subpath and not the root entry.** Since the protect-ffi native load
 * became lazy, importing that package proves nothing: `@neon-rs/load`'s proxy
 * resolves the platform binary on first property access, inside a wrapper body,
 * so a missing binary imports cleanly and fails later at the first encrypt.
 * Nor can a caller force it from outside — `@cipherstash/protect-ffi/lib/load.cjs`
 * is not in that package's `exports` (`ERR_PACKAGE_PATH_NOT_EXPORTED`), and
 * touching an export never reaches the proxy because the exports are
 * protect-ffi's own wrapper functions. CALLING one is what reaches it.
 *
 * **Why not `@cipherstash/stack` itself.** The root entry re-exports the auth
 * strategies, which means evaluating it reads a property off
 * `@cipherstash/auth` — a NAPI module whose entry is `module.exports = {
 * ...native }`, eager on both counts. So a probe that imports the root entry
 * measures AUTH's binary and reports it as the encryption engine's. This module
 * imports protect-ffi and nothing else, so the signal belongs to the package
 * named in the row.
 *
 * **Why `isEncrypted` and not protect-ffi's own `assertNativeBindingAvailable`,
 * which is this function's twin.** That export does not exist in any version of
 * protect-ffi on npm. It arrived with the lazy load, whose changeset is parked
 * as `.deferred` until the publishing cutover, so no released version carries
 * it — and `@cipherstash/stack` depends on `workspace:*`, which resolves to the
 * sibling directory here and to a published version for everyone else. A
 * re-export would therefore work in this repo and fail everywhere it shipped:
 * under ESM at import, with a link-time SyntaxError, and under CJS as an
 * `undefined` that is not a function. `isEncrypted` has been published since
 * 0.28.0 and is the call protect-ffi's own assert makes, for the same reason —
 * it is pure, synchronous, and validates nothing before reaching the addon, so
 * whatever it raises came from the loader.
 *
 * Kept pure deliberately: no side effects at module scope, and the loader's
 * error is not caught, wrapped or re-thrown anywhere on the path — a caller
 * classifying `MODULE_NOT_FOUND` sees exactly what the loader raised.
 */
export function assertNativeBindingAvailable(): void {
  isEncrypted(null)
}
