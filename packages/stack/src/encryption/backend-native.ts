import * as ffi from '@cipherstash/protect-ffi'
import type { CryptoBackend } from './backend'

/**
 * {@link CryptoBackend} over the Node-API binding.
 *
 * **This module is the only place in the operation path that value-imports
 * `@cipherstash/protect-ffi`.** That is the point: a value import of the
 * Node-API entry loads a native binary, so any module reachable from it is
 * unusable in a V8 isolate. Confining it here is what lets the operation
 * classes be shared with `@cipherstash/stack/wasm-inline`, which injects its
 * own backend over `@cipherstash/protect-ffi/wasm-inline`.
 *
 * Nothing may import this module from code the WASM entry can reach. A build
 * test asserts the shipped `dist/wasm-inline.js` contains no reference to the
 * Node-API specifier — that assertion is what keeps the separation real rather
 * than conventional (cipherstash/stack#798).
 *
 * The functions are passed through untouched; see {@link CryptoBackend} for
 * why this stays a bare re-export rather than growing behaviour.
 *
 * Each method delegates through the namespace rather than closing over a
 * destructured import, so a binding is read at CALL time. That keeps partial
 * `vi.mock('@cipherstash/protect-ffi', …)` in existing suites working: binding
 * all six eagerly would make every test that stubs only the function it
 * exercises fail at module load, on an export it never calls.
 */
export const nativeBackend: CryptoBackend = {
  encrypt: (client, opts) => ffi.encrypt(client, opts),
  decrypt: (client, opts) => ffi.decrypt(client, opts),
  encryptBulk: (client, opts) => ffi.encryptBulk(client, opts),
  decryptBulkFallible: (client, opts) => ffi.decryptBulkFallible(client, opts),
  encryptQuery: (client, opts) => ffi.encryptQuery(client, opts),
  encryptQueryBulk: (client, opts) => ffi.encryptQueryBulk(client, opts),
}
