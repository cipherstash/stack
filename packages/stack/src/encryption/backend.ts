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
 *
 * ## What both backends must agree on
 *
 * The point of one interface is that the two entries cannot drift. These are
 * the invariants that makes true — none of them are enforced by the type
 * system alone, so they are stated here rather than discovered per binding:
 *
 * 1. **The three bulk calls preserve order.** Callers re-associate results
 *    with inputs *positionally*, so a returned array must have the same length
 *    as its input and the same ordering. A backend that reorders or compacts
 *    mis-assigns ciphertexts to rows, silently and irreversibly.
 * 2. **Failure is a rejection, not a sentinel.** Every method throws on error;
 *    the operation classes wrap the call in `withResult` and turn that into
 *    `{ failure }`. The one exception is per-item decrypt failure, which
 *    {@link CryptoBackend.decryptBulkFallible} reports in-band.
 * 3. **`lockContext` sits in different places on the single and bulk calls.**
 *    Single calls take it at the top level of `opts`; the bulk calls take it
 *    on each payload item. See the per-method notes.
 * 4. **`unverifiedContext` is always top-level, and is audit metadata only.**
 *    It reaches the ZeroKMS audit log and is *not* bound into key derivation,
 *    so it never affects whether a value can be read back. Contrast
 *    `lockContext`, which does.
 *
 * These types come from the Node-API `.d.ts`, which states the option shapes
 * explicitly. The WASM binding types every `opts` as `any` across its serde
 * boundary, so for the WASM path this interface is the *only* thing checking
 * that a call is well-formed — one more reason to keep it a faithful
 * restatement rather than a convenient one.
 */
export interface CryptoBackend {
  /**
   * Encrypt one value for storage in one column.
   *
   * Reached only with a validated, non-null plaintext: the operation layer
   * short-circuits `null` (so a NULL column stays NULL rather than becoming an
   * encrypted JSON null) and rejects NaN, ±Infinity, and out-of-int64 `bigint`
   * before this point.
   *
   * `opts.lockContext` binds the derived data key to an identity claim. The
   * same claim must be supplied to {@link CryptoBackend.decrypt} to read the
   * value back.
   */
  encrypt(
    client: LiveClient,
    opts: FfiEncryptOptions,
  ): Promise<EncryptedPayload>

  /**
   * Decrypt one stored payload, in either wire format — EQL v2 or v3. The
   * client writes v3 only; both bindings still read v2 for migrating callers.
   *
   * A payload encrypted under a lock context can only be decrypted by
   * supplying the same claim: the context changes key derivation, so it is
   * part of the ciphertext's identity rather than a check applied afterwards.
   */
  decrypt(client: LiveClient, opts: DecryptOptions): Promise<JsPlaintext>

  /**
   * Encrypt many values in one ZeroKMS round trip — the fast path, and the
   * reason to prefer `bulkEncrypt*` over a loop.
   *
   * Each payload names its own `table` and `column`, so one batch may span
   * both; there is no single-column restriction.
   *
   * All-or-nothing. Unlike {@link CryptoBackend.decryptBulkFallible} there is
   * no per-item error channel, so one bad item rejects the whole call.
   *
   * `lockContext` goes on each `EncryptPayload`, NOT at the top level — the
   * asymmetry with {@link CryptoBackend.encrypt} is easy to trip over. The
   * Node-API types reject the misplaced version at compile time; the WASM
   * binding, typing `opts` as `any`, would accept and drop it. Only this
   * interface stands between that and a value encrypted without the context
   * its caller asked for.
   */
  encryptBulk(
    client: LiveClient,
    opts: EncryptBulkOptions,
  ): Promise<EncryptedPayload[]>

  /**
   * Decrypt many payloads in one round trip, reporting failures per item.
   *
   * The fallible variant is the one both entries use: an item that cannot be
   * decrypted arrives as `{ error }` in place of `{ data }`, so a single
   * unreadable row — wrong lock context, rotated-away key — does not cost the
   * caller the whole batch. The non-fallible `decryptBulk` rejects instead,
   * which is why it is deliberately absent from this interface.
   *
   * Position still carries the association between input and result, so the
   * array is the same length and order as `opts.ciphertexts` whether an item
   * succeeded or not.
   *
   * `lockContext` is per item here too, on each `BulkDecryptPayload`.
   */
  decryptBulkFallible(
    client: LiveClient,
    opts: DecryptBulkOptions,
  ): Promise<DecryptResult[]>

  /**
   * Encrypt one value into a *query term*.
   *
   * Distinct from {@link CryptoBackend.encrypt}: the result is a term to match
   * against an index, not a payload to store. `indexType` and `queryOp` select
   * which term to generate, and the return shape varies with that choice —
   * hence the union. `formatEncryptedResult` narrows it for the caller.
   */
  encryptQuery(
    client: LiveClient,
    opts: EncryptQueryOptions,
  ): Promise<FfiEncrypted | EncryptedQuery | EncryptedV3Query>

  /**
   * Encrypt many query terms in one round trip.
   *
   * Terms are independent — each `QueryPayload` names its own table, column,
   * index type, and lock context — so one batch may span columns and tables.
   *
   * Order is the association: the caller filters null terms out beforehand and
   * slots these results back into the positions it kept.
   */
  encryptQueryBulk(
    client: LiveClient,
    opts: EncryptQueryBulkOptions,
  ): Promise<(FfiEncrypted | EncryptedQuery | EncryptedV3Query)[]>
}
