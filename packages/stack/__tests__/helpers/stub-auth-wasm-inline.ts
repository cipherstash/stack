/**
 * Test stub for `@cipherstash/auth/wasm-inline`.
 *
 * See {@link file://./stub-protect-ffi-wasm-inline.ts} — the `/wasm-inline`
 * subpath is not exported by the installed `@cipherstash/auth`, so this stub
 * lets Vitest load `src/wasm-inline` for pure-helper unit tests. Aliased in via
 * `vitest.config.ts`.
 */
export const AccessKeyStrategy = {
  create: (): never => {
    throw new Error(
      '[test stub]: auth/wasm-inline AccessKeyStrategy.create not implemented',
    )
  },
}
