import type { Result } from '@byteslice/result'
import type { EncryptionError } from '@/errors'

export type AuditConfig = {
  metadata?: Record<string, unknown>
}

export type AuditData = {
  metadata?: Record<string, unknown>
}

/**
 * Base class for the chainable, awaitable operations the client returns.
 *
 * An operation is **both** a builder and a promise: `.audit()` /
 * `.withLockContext()` return `this`, and awaiting it runs `execute()` and
 * resolves to a `Result`. The two are not alternatives — a caller can do
 * either, or both.
 *
 * ## Why it implements the full `Promise` interface
 *
 * `then` alone makes a value awaitable, but TypeScript's `Promise<T>` is
 * structural and requires `then`, `catch`, `finally`, and
 * `[Symbol.toStringTag]`. With only `then`, an operation is *not* assignable
 * to `Promise<…>`, so `const p: Promise<Result<…>> = client.encrypt(…)` fails
 * to compile and `.catch(…)` does not exist.
 *
 * That mattered once the WASM entry was in play. `wasm-inline` returns bare
 * `Promise<WasmResult<T>>`, so having it return these operations instead —
 * the whole point of sharing one operation layer (#798) — would have been a
 * breaking change for anyone who annotated the old return type. Implementing
 * the remaining three members removes that: the operation is assignable
 * wherever a `Promise` was, so adopting it on the WASM entry is additive, and
 * `.audit()` / `.withLockContext()` arrive there without a major bump.
 *
 * All three delegate to `execute()` exactly as `then` does. They add no
 * behaviour; they exist so the structural check passes and so `.catch()` /
 * `.finally()` work on an operation the way callers already expect.
 */
export abstract class EncryptionOperation<T>
  implements Promise<Result<T, EncryptionError>>
{
  protected auditMetadata?: Record<string, unknown>

  /**
   * Attach audit metadata to this operation. Can be chained.
   * @param config Configuration for ZeroKMS audit logging
   * @param config.metadata Arbitrary JSON object for appending metadata to the audit log
   */
  audit(config: AuditConfig): this {
    this.auditMetadata = config.metadata
    return this
  }

  /**
   * Get the audit data for this operation.
   */
  public getAuditData(): AuditData {
    return {
      metadata: this.auditMetadata,
    }
  }

  /**
   * Execute the operation and return a Result
   */
  abstract execute(): Promise<Result<T, EncryptionError>>

  /**
   * Make the operation thenable
   */
  public then<TResult1 = Result<T, EncryptionError>, TResult2 = never>(
    onfulfilled?:
      | ((
          value: Result<T, EncryptionError>,
        ) => TResult1 | PromiseLike<TResult1>)
      | null,
    onrejected?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null,
  ): Promise<TResult1 | TResult2> {
    return this.execute().then(onfulfilled, onrejected)
  }

  /**
   * Rejection handler, for parity with a promise.
   *
   * Note what this does NOT catch: an operation that fails *expectedly*
   * resolves to `{ failure }` rather than rejecting, per the Result contract.
   * This only fires on a thrown exception — the same cases `await` would
   * throw on. Check `.failure` on the resolved value for everything else.
   */
  public catch<TResult = never>(
    onrejected?: ((reason: unknown) => TResult | PromiseLike<TResult>) | null,
  ): Promise<Result<T, EncryptionError> | TResult> {
    return this.execute().catch(onrejected)
  }

  /** Runs on settle, for parity with a promise. */
  public finally(
    onfinally?: (() => void) | null,
  ): Promise<Result<T, EncryptionError>> {
    return this.execute().finally(onfinally)
  }

  /**
   * Present so the class satisfies `Promise<T>` structurally. Reported as the
   * concrete operation name rather than `'Promise'`, so a logged or inspected
   * operation is not mistaken for one.
   */
  public get [Symbol.toStringTag](): string {
    return this.constructor.name
  }
}
