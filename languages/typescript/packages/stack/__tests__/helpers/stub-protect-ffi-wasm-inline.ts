/**
 * Test stub for `@cipherstash/protect-ffi/wasm-inline`.
 *
 * These no-op stubs let the unit tests that only exercise pure helpers
 * (`getColumnName`, `normalizeCastAs`) load `src/wasm-inline` without paying
 * for the real 4MB inlined-WASM module. Aliased in via `vitest.shared.ts`
 * (`stackSourceAlias`). Any test that actually needs WASM behaviour must mock
 * it explicitly (see `wasm-inline-column-name.test.ts`).
 *
 * The alias is a convenience, not a necessity: `@cipherstash/protect-ffi`
 * does export `./wasm-inline` as of 0.30.0, and
 * `wasm-inline-core-credential-contract.test.ts` deliberately bypasses this
 * stub to assert against the real core.
 */
export const decrypt = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline decrypt not implemented',
  )
}

export const decryptBulkFallible = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline decryptBulkFallible not implemented',
  )
}

export const encrypt = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline encrypt not implemented',
  )
}

export const encryptBulk = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline encryptBulk not implemented',
  )
}

export const encryptQuery = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline encryptQuery not implemented',
  )
}

export const encryptQueryBulk = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline encryptQueryBulk not implemented',
  )
}

export const isEncrypted = (): boolean => false

/**
 * NOT a stub — the real predicate, re-exported.
 *
 * `src/wasm-inline.ts` validates `failure.code` against the closed
 * `ProtectErrorCode` set with this, exactly as the native entry does. Stubbing
 * it would let a wrong answer pass: a hand-written `() => true` republishes
 * `ECONNRESET` as an encryption error code and the test that exists to catch
 * that would go green.
 *
 * Imported from the package root rather than `/wasm-inline` — this file IS the
 * stand-in for that subpath, whose runtime target (`protect_ffi_inline.js`) is
 * a wasm-pack output that only exists after a Rust build. The root resolves to
 * the built `lib/`, and the two are the same function from the same
 * `src/errors.ts`. The no-native-import rule that shapes `src/wasm-inline.ts`
 * is about what lands in the shipped bundle; nothing here is shipped.
 */
export { isProtectErrorCode } from '@cipherstash/protect-ffi'

export const newClient = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline newClient not implemented',
  )
}
