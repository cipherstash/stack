/**
 * Per-process registry of `CipherstashSdk` instances that have been
 * wired up via `bulkEncryptMiddleware(sdk)`. The codec's `encode`
 * consults this registry to fire a misconfig diagnostic when an
 * SDK-bound codec sees a pre-encrypt envelope without a corresponding
 * middleware registration — the failure mode is otherwise an opaque
 * pg-level serialise error.
 *
 * Keyed on `CipherstashSdk` reference identity via a `WeakSet`, so
 * multi-tenant deployments that construct one SDK per tenant
 * correctly distinguish each tenant's middleware lifecycle, and no
 * strong references leak.
 */

import type { CipherstashSdk } from './sdk'

const REGISTERED: WeakSet<CipherstashSdk> = new WeakSet()

export function markBulkEncryptMiddlewareRegistered(sdk: CipherstashSdk): void {
  REGISTERED.add(sdk)
}

export function isBulkEncryptMiddlewareRegistered(
  sdk: CipherstashSdk,
): boolean {
  return REGISTERED.has(sdk)
}
