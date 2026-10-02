/**
 * Test stub for `@cipherstash/auth/wasm-inline`.
 *
 * See {@link file://./stub-protect-ffi-wasm-inline.ts} — the `/wasm-inline`
 * subpath is not exported by the installed `@cipherstash/auth`, so this stub
 * lets Vitest load `src/wasm-inline` for pure-helper unit tests. Aliased in via
 * `vitest.config.ts`.
 */
// `@cipherstash/auth` `0.41` `create` returns a `Result<Strategy, AuthFailure>`
// rather than throwing. These stubs are only reached by tests that don't
// override the module with `vi.mock`; they still throw loudly so an
// unexpectedly-exercised path fails visibly rather than silently.
export const AccessKeyStrategy = {
  create: (): never => {
    throw new Error(
      '[test stub]: auth/wasm-inline AccessKeyStrategy.create not implemented',
    )
  },
}

export const OidcFederationStrategy = {
  create: (): never => {
    throw new Error(
      '[test stub]: auth/wasm-inline OidcFederationStrategy.create not implemented',
    )
  },
}
