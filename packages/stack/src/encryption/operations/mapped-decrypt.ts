import type { Result } from '@byteslice/result'
import type { EncryptionError } from '@/errors'
import type { LockContextInput } from '@/identity'
import { type AuditConfig, EncryptionOperation } from './base-operation'

/**
 * The subset of an underlying decrypt operation the mapped wrapper drives: a
 * chainable {@link EncryptionOperation} that MAY additionally expose
 * `.withLockContext()`. A lock-bound underlying op (e.g.
 * `DecryptModelOperationWithLockContext`) has already consumed its lock context
 * and offers no further `withLockContext`, so the method is optional here.
 */
type UnderlyingDecryptOperation<In> = EncryptionOperation<In> & {
  withLockContext?: (lockContext: LockContextInput) => EncryptionOperation<In>
}

/**
 * The public contract of a decrypt-model operation returned by the typed client:
 * awaitable to a `Result<Out, …>`, and chainable with `.audit()` /
 * `.withLockContext()`. Hides the underlying pre-map type parameter.
 */
export interface AuditableDecryptModelOperation<Out>
  extends EncryptionOperation<Out> {
  audit(config: AuditConfig): this
  /**
   * @throws if the operation already took a lock context positionally — bind it
   * once, either positionally or by chaining.
   */
  withLockContext(
    lockContext: LockContextInput,
  ): AuditableDecryptModelOperation<Out>
}

/**
 * A chainable decrypt operation that maps a successful result through a pure,
 * precomputed function while delegating audit metadata and lock context to the
 * underlying operation it wraps.
 *
 * This is what lets the typed EQL v3 client carry `.audit()` /
 * `.withLockContext()` on `decryptModel` / `bulkDecryptModels`: the earlier
 * implementation `await`ed the underlying op and mapped the resolved value,
 * which collapsed the chain to a plain `Promise<Result<…>>` and dropped both
 * capabilities. Here the mapping runs inside `execute()` instead, so the
 * operation stays an {@link EncryptionOperation} the whole way.
 *
 * - `.audit()` forwards to the underlying op, so the op that actually runs the
 *   decrypt sees the metadata (via `getAuditData()`), in EITHER chaining order —
 *   `.audit().withLockContext()` propagates because `withLockContext` copies the
 *   audit data forward, and `.withLockContext().audit()` propagates because the
 *   wrapper forwards `.audit()` onto the now-lock-bound underlying op.
 * - `.withLockContext()` rebuilds the wrapper over `underlying.withLockContext(lc)`,
 *   preserving the same `map` and unknown-table failure. It throws if the
 *   underlying op is already lock-bound (a positional lock context followed by a
 *   chained one), because the wrapper — unlike the nominal path — still exposes
 *   the method after binding, so the second call would otherwise be dropped.
 * - `execute()` never throws: an unknown table (no `map`) returns the precomputed
 *   `failure` Result, and `map` is a precomputed reconstructor — pure, no
 *   `build()` — so it cannot reject the Result contract.
 */
export class MappedDecryptOperation<In, Out> extends EncryptionOperation<Out> {
  constructor(
    private readonly underlying: UnderlyingDecryptOperation<In>,
    // Precomputed reconstructor. `undefined` when the table is unknown to the
    // client — `execute()` then short-circuits to `unknownTableFailure`.
    private readonly map: ((value: In) => Out) | undefined,
    private readonly unknownTableFailure: { failure: EncryptionError },
  ) {
    super()
  }

  override audit(config: AuditConfig): this {
    // Delegate to the op that runs the decrypt so its `execute()` sees the
    // metadata; the wrapper's own `execute()` reads nothing off `this`.
    this.underlying.audit(config)
    return this
  }

  withLockContext(
    lockContext: LockContextInput,
  ): MappedDecryptOperation<In, Out> {
    // A lock-bound underlying op exposes no `withLockContext` — it has already
    // consumed its context. Unlike the nominal path, where the method is simply
    // absent after binding, the wrapper always exposes it, so a second bind
    // type-checks. Silently keeping the first would drop the caller's intent and
    // surface later as an opaque ZeroKMS rejection; reject it here instead.
    if (!this.underlying.withLockContext) {
      throw new Error(
        '[encryption]: this decrypt operation is already bound to a lock context. Pass the lock context positionally OR chain .withLockContext() — not both.',
      )
    }
    return new MappedDecryptOperation(
      this.underlying.withLockContext(lockContext),
      this.map,
      this.unknownTableFailure,
    )
  }

  override async execute(): Promise<Result<Out, EncryptionError>> {
    if (!this.map) {
      // Fresh Result so no two ops can alias (or mutate) a shared failure object.
      return { failure: { ...this.unknownTableFailure.failure } }
    }
    const result = await this.underlying.execute()
    if (result.failure) {
      return result
    }
    return { data: this.map(result.data) }
  }
}
