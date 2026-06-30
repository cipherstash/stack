/**
 * Tests for the optional `config.strategy` auth strategy.
 *
 * protect-ffi (0.25+) lets `newClient` take an `AuthStrategy` (any
 * `{ getToken(): Promise<{ token }> }` object — the shape every
 * `@cipherstash/auth` strategy satisfies, including
 * `OidcFederationStrategy` for per-user identity-bound encryption).
 * `Encryption` exposes it via `config.strategy`; when provided it must
 * reach `newClient` as `opts.strategy`, and when omitted the option must
 * be absent so the default credentials-derived strategy is used.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'
import type { AuthStrategy } from '@/types'

vi.mock('@cipherstash/protect-ffi', () => ({
  newClient: vi.fn(async () => ({ __mock: 'client' })),
}))

import * as ffi from '@cipherstash/protect-ffi'

const users = encryptedTable('users', {
  email: encryptedColumn('email'),
})

beforeEach(() => {
  vi.clearAllMocks()
})

describe('Encryption config.strategy', () => {
  it('forwards a supplied strategy to newClient', async () => {
    const strategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({ schemas: [users], config: { strategy } })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(strategy)
  })

  it('passes the strategy alongside the credential clientOpts', async () => {
    const strategy: AuthStrategy = {
      getToken: vi.fn(async () => ({ token: 'service-token' })),
    }

    await Encryption({
      schemas: [users],
      config: {
        strategy,
        workspaceCrn: 'crn:ap-southeast-2.aws:test-workspace',
        clientId: 'client-id',
        clientKey: 'client-key',
      },
    })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(strategy)
    // clientKey is still required even when a strategy is supplied.
    expect(opts.clientOpts.clientKey).toBe('client-key')
    expect(opts.clientOpts.workspaceCrn).toBe(
      'crn:ap-southeast-2.aws:test-workspace',
    )
  })

  it('forwards an OidcFederationStrategy-shaped strategy to newClient', async () => {
    // Mirror `OidcFederationStrategy`'s public shape (getToken returning a
    // TokenResult) without loading the native `@cipherstash/auth` binding —
    // `Encryption` forwards the object opaquely, so its concrete type is
    // irrelevant to this wiring.
    const oidcStrategy: AuthStrategy = {
      getToken: vi.fn(async () => ({
        token: 'cts-service-token',
        subject: 'CS|auth0|user123',
        workspaceId: 'test-workspace',
        issuer: 'https://cts.example',
        services: { zerokms: 'https://zerokms.example' },
      })),
    }

    await Encryption({ schemas: [users], config: { strategy: oidcStrategy } })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBe(oidcStrategy)
  })

  it('leaves strategy undefined when none is supplied', async () => {
    await Encryption({ schemas: [users] })

    // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
    const opts = vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any
    expect(opts.strategy).toBeUndefined()
  })
})
