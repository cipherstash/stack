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
import { EncryptionV3 } from '@/encryption/v3'
import { Encryption } from '@/index'
import { encryptedColumn, encryptedTable } from '@/schema'
import type { AuthStrategy, BuildableTable } from '@/types'

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

// A minimal structural EQL v3 table: what marks a table as v3 for wire-format
// detection is its `buildColumnKeyMap()` method (v2 tables have none). Built
// by hand rather than via `@cipherstash/stack/v3` so this suite pins the
// structural contract `Encryption` actually dispatches on.
const v3Table = (tableName = 'v3_users'): BuildableTable =>
  ({
    tableName,
    build: () => ({
      tableName,
      columns: { email: { cast_as: 'text', indexes: { unique: {} } } },
    }),
    buildColumnKeyMap: () => ({ email: 'email' }),
  }) as BuildableTable

describe('Encryption config.eqlVersion', () => {
  // biome-ignore lint/suspicious/noExplicitAny: reading recorded mock args
  const lastNewClientOpts = () =>
    vi.mocked(ffi.newClient).mock.calls.at(-1)![0] as any

  it('leaves eqlVersion undefined for a v2 schema set (FFI default, byte-identical v2 wire)', async () => {
    await Encryption({ schemas: [users] })

    expect(lastNewClientOpts().eqlVersion).toBeUndefined()
  })

  it('auto-detects eqlVersion 3 when every schema is a v3 table', async () => {
    await Encryption({ schemas: [v3Table()] })

    expect(lastNewClientOpts().eqlVersion).toBe(3)
  })

  it('forwards an explicit eqlVersion for a v2 schema set', async () => {
    await Encryption({ schemas: [users], config: { eqlVersion: 3 } })

    expect(lastNewClientOpts().eqlVersion).toBe(3)
  })

  it('lets an explicit eqlVersion 2 override v3 auto-detection (migration escape hatch)', async () => {
    await Encryption({ schemas: [v3Table()], config: { eqlVersion: 2 } })

    expect(lastNewClientOpts().eqlVersion).toBe(2)
  })

  it('throws on a mixed v2 + v3 schema set — one client emits one wire format', async () => {
    await expect(Encryption({ schemas: [users, v3Table()] })).rejects.toThrow(
      /cannot mix EQL v2 and EQL v3 tables/,
    )
  })

  it('throws on a mixed schema set even with an explicit eqlVersion', async () => {
    await expect(
      Encryption({ schemas: [users, v3Table()], config: { eqlVersion: 3 } }),
    ).rejects.toThrow(/cannot mix EQL v2 and EQL v3 tables/)
  })

  it('EncryptionV3 creates the underlying client with eqlVersion 3', async () => {
    // The duck-typed table satisfies the runtime contract; the type-level
    // AnyV3Table constraint is beside the point for this wiring assertion.
    await EncryptionV3({ schemas: [v3Table() as never] })

    expect(lastNewClientOpts().eqlVersion).toBe(3)
  })

  it('EncryptionV3 honours an explicit eqlVersion override', async () => {
    await EncryptionV3({
      schemas: [v3Table() as never],
      config: { eqlVersion: 2 },
    })

    expect(lastNewClientOpts().eqlVersion).toBe(2)
  })
})
