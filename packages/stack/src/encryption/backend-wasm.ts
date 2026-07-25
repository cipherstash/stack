import * as ffi from '@cipherstash/protect-ffi/wasm-inline'
import type { CryptoBackend } from './backend'

/**
 * {@link CryptoBackend} over the WASM binding — the mirror of
 * `backend-native.ts`, and the reason the operation classes can be shared
 * (#798).
 *
 * The two bindings expose the same six functions with the same `(client, opts)`
 * shape; only the import specifier differs. `@cipherstash/protect-ffi/wasm-inline`
 * types its `opts` as `any` because they cross a serde boundary into the same
 * Rust core the Node-API entry calls, so the casts below assert the shape the
 * NAPI `.d.ts` states explicitly rather than inventing one.
 *
 * **Nothing here may import the Node-API entry.** That is the whole point:
 * `dist/wasm-inline.js` must contain no bare `@cipherstash/protect-ffi`
 * specifier, and `__tests__/wasm-inline-bundle-isolation.test.ts` asserts it
 * against the built artifact.
 *
 * Delegates through the namespace rather than destructuring, for the same
 * reason as the native backend: bindings resolve at call time, so a partial
 * module mock in a test does not fail on the functions it never exercises.
 */
export const wasmBackend: CryptoBackend = {
  // biome-ignore lint/plugin: the wasm binding types every `opts` as `any` across the serde boundary
  encrypt: (client, opts) => ffi.encrypt(client as never, opts as never),
  // biome-ignore lint/plugin: as above
  decrypt: (client, opts) => ffi.decrypt(client as never, opts as never),
  // biome-ignore lint/plugin: as above
  encryptBulk: (client, opts) =>
    ffi.encryptBulk(client as never, opts as never),
  // biome-ignore lint/plugin: as above
  decryptBulkFallible: (client, opts) =>
    ffi.decryptBulkFallible(client as never, opts as never),
  // biome-ignore lint/plugin: as above
  encryptQuery: (client, opts) =>
    ffi.encryptQuery(client as never, opts as never),
  // biome-ignore lint/plugin: as above
  encryptQueryBulk: (client, opts) =>
    ffi.encryptQueryBulk(client as never, opts as never),
}
