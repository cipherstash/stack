import { afterEach, describe, expect, it } from 'vitest'
import { clerkJwtProvider } from '@cipherstash/test-kit/integration-clerk'

/**
 * `clerkJwtProvider`'s "FAIL rather than skip" guard is the load-bearing half of
 * the identity suites' no-silent-skip contract: if it were ever weakened to a
 * skip or a silent `undefined`, the entire identity suite would go dark while CI
 * stayed green. The throw is pure logic — it fires before `createClerkClient`,
 * so it needs no live Clerk and belongs here in the credential-free unit suite
 * rather than the integration config (which only globs `*.integration.test.ts`).
 */
describe('clerkJwtProvider', () => {
  const saved = process.env.CLERK_MACHINE_TOKEN
  const savedB = process.env.CLERK_MACHINE_TOKEN_B
  afterEach(() => {
    if (saved === undefined) delete process.env.CLERK_MACHINE_TOKEN
    else process.env.CLERK_MACHINE_TOKEN = saved
    if (savedB === undefined) delete process.env.CLERK_MACHINE_TOKEN_B
    else process.env.CLERK_MACHINE_TOKEN_B = savedB
  })

  it('throws (does not skip) when the default machine token env var is unset', () => {
    delete process.env.CLERK_MACHINE_TOKEN
    expect(() => clerkJwtProvider()).toThrow(/missing CLERK_MACHINE_TOKEN/)
  })

  it('names the custom env var it was handed', () => {
    delete process.env.CLERK_MACHINE_TOKEN_B
    expect(() => clerkJwtProvider('CLERK_MACHINE_TOKEN_B')).toThrow(
      /CLERK_MACHINE_TOKEN_B/,
    )
  })
})
