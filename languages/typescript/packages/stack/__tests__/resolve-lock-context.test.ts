/**
 * Offline unit tests for the synchronous lock-context surface of
 * `src/identity/index.ts`.
 *
 * - `resolveLockContext` is the synchronous branch that replaced the old
 *   `await getLockContext()` flow in every operation. It's otherwise only
 *   exercised indirectly via `new LockContext()`, whose default context is
 *   `{ identityClaim: ['sub'] }` — so a regression where the `LockContext`
 *   branch returned a hardcoded `['sub']` (instead of the constructed claim)
 *   would pass every existing test, including `lock-context-wiring.test.ts`.
 * - `LockContext.getLockContext()`'s contract changed in this PR: the guard
 *   that threw when no CTS token was set is gone, and `ctsToken` may now be
 *   `undefined`. Deprecated and low priority, but the new non-throwing
 *   behaviour has no other coverage.
 */

import { beforeAll, describe, expect, it } from 'vitest'
import { LockContext, resolveLockContext } from '@/identity'

beforeAll(() => {
  // LockContext's constructor resolves the workspace id from the env.
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
})

describe('resolveLockContext', () => {
  it('returns a plain Context input unchanged', () => {
    const ctx = { identityClaim: ['email'] }
    expect(resolveLockContext(ctx)).toBe(ctx)
  })

  it('extracts the constructed claim from a LockContext (not the default)', () => {
    const lc = new LockContext({ context: { identityClaim: ['email'] } })
    expect(resolveLockContext(lc)).toEqual({ identityClaim: ['email'] })
  })
})

describe('LockContext.getLockContext (deprecated)', () => {
  it('resolves without throwing and reports no CTS token when none was set', async () => {
    const result = await new LockContext().getLockContext()
    expect(result.failure).toBeUndefined()
    expect(result.data.ctsToken).toBeUndefined()
    expect(result.data.context).toEqual({ identityClaim: ['sub'] })
  })
})
