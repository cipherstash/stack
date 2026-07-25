import type {
  DecryptBulkOptions,
  DecryptOptions,
  DecryptResult,
  EncryptBulkOptions,
  EncryptedPayload,
  EncryptedQuery,
  EncryptedV3Query,
  EncryptQueryBulkOptions,
  EncryptQueryOptions,
  Encrypted as FfiEncrypted,
  EncryptOptions as FfiEncryptOptions,
  JsPlaintext,
} from '@cipherstash/protect-ffi'
import type { Client } from '@/types'

/**
 * The FFI requires a live client handle. `Client` from `@/types` is
 * `… | undefined`, because the public client may not have initialised yet —
 * every operation already guards with `noClientError()` before reaching the
 * backend, so the narrowed handle is what actually crosses this boundary.
 */
type LiveClient = NonNullable<Client>

/**
 * The cryptographic primitives an operation needs, as an injected dependency
 * rather than a module import.
 *
 * ## Why this exists
 *
 * `@cipherstash/stack` ships two runtime entries. The default one binds
 * `@cipherstash/protect-ffi` (Node-API); `@cipherstash/stack/wasm-inline`
 * binds `@cipherstash/protect-ffi/wasm-inline`. The two bindings expose the
 * SAME six functions with the same `(client, opts)` shape — they differ only
 * in import specifier.
 *
 * Before this interface, the operation classes reached their binding by
 * module-level `import`. A value import of the Node-API entry is not merely a
 * dependency, it is a *runtime load* of a native binary, which cannot happen
 * in a V8 isolate. So nothing that imported an operation class could be reused
 * on the edge, and `wasm-inline.ts` reimplemented the whole client surface
 * against the other binding — where it then drifted on call shape, and never
 * gained `.audit()` or `.withLockContext()`.
 *
 * Injecting the backend removes the reason for that split: one operation
 * layer, two backends. See cipherstash/stack#798.
 *
 * ## What this deliberately is NOT
 *
 * Not an abstraction over *encryption*. It is a 1:1 restatement of the FFI
 * surface, so that swapping bindings is the only thing it enables. Adding
 * behaviour here (retries, caching, validation) would put logic below the
 * operation classes where the Result contract and the audit/lock-context
 * plumbing live, and both entries would silently inherit it. Keep it boring.
 *
 * The `Client` handle is already injected separately (operations take it in
 * their constructor), so it stays a parameter here rather than being captured
 * — a backend is stateless and safe to share across clients.
 */
export interface CryptoBackend {
  encrypt(
    client: LiveClient,
    opts: FfiEncryptOptions,
  ): Promise<EncryptedPayload>

  decrypt(client: LiveClient, opts: DecryptOptions): Promise<JsPlaintext>

  encryptBulk(
    client: LiveClient,
    opts: EncryptBulkOptions,
  ): Promise<EncryptedPayload[]>

  /**
   * The fallible variant is the one both entries use: bulk decrypt reports
   * per-item errors, unlike bulk encrypt which ZeroKMS rejects as a whole.
   */
  decryptBulkFallible(
    client: LiveClient,
    opts: DecryptBulkOptions,
  ): Promise<DecryptResult[]>

  encryptQuery(
    client: LiveClient,
    opts: EncryptQueryOptions,
  ): Promise<FfiEncrypted | EncryptedQuery | EncryptedV3Query>

  encryptQueryBulk(
    client: LiveClient,
    opts: EncryptQueryBulkOptions,
  ): Promise<(FfiEncrypted | EncryptedQuery | EncryptedV3Query)[]>
}
