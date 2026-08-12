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
 * protect-ffi's own wrapper functions. `assertNativeBindingAvailable()` is the
 * named operation that does reach it.
 *
 * **Why not `@cipherstash/stack` itself.** The root entry re-exports the auth
 * strategies, which means evaluating it reads a property off
 * `@cipherstash/auth` — a NAPI module whose entry is `module.exports = {
 * ...native }`, eager on both counts. So a probe that imports the root entry
 * measures AUTH's binary and reports it as the encryption engine's. This module
 * imports protect-ffi and nothing else, so the signal belongs to the package
 * named in the row.
 *
 * Kept pure deliberately: no side effects at module scope, and the loader's
 * error is not caught, wrapped or re-thrown anywhere on the path — a caller
 * classifying `MODULE_NOT_FOUND` sees exactly what the loader raised.
 */
export { assertNativeBindingAvailable } from '@cipherstash/protect-ffi'
