/**
 * Test stub for `@cipherstash/protect-ffi/wasm-inline`.
 *
 * The installed `@cipherstash/protect-ffi` only exports `.` — the `/wasm-inline`
 * subpath does not exist, so Vitest cannot resolve `src/wasm-inline` (which
 * imports it). These no-op stubs let the unit tests that only exercise pure
 * helpers (`getColumnName`, `normalizeCastAs`) load the module. Aliased in via
 * `vitest.config.ts`. Any test that actually needs WASM behaviour must mock it
 * explicitly (see `wasm-inline-column-name.test.ts`).
 */
export const decrypt = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline decrypt not implemented',
  )
}

export const encrypt = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline encrypt not implemented',
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

export const newClient = (): never => {
  throw new Error(
    '[test stub]: protect-ffi/wasm-inline newClient not implemented',
  )
}
