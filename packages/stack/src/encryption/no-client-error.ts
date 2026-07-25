/**
 * Raised when an operation runs before its client finished initialising.
 *
 * Lives in its own module rather than in `encryption/index.ts` because every
 * operation class needs it, and `encryption/index.ts` is the native entry's
 * composition root — it value-imports `backend-native.ts`, and through it the
 * Node-API binding. Importing `noClientError` from there would drag the native
 * binary into any bundle that touches an operation, which is precisely what
 * `@cipherstash/stack/wasm-inline` must never do (#798).
 *
 * Re-exported from `encryption/index.ts` so the public path is unchanged.
 */
export const noClientError = () =>
  new Error(
    'The Encryption client has not been initialized. Please call init() before using the client.',
  )
