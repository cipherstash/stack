/**
 * Offline unit tests for the WASM entry's environment-variable credential
 * fallback.
 *
 * The native entry gets this for free: an omitted credential resolves from env
 * or `~/.cipherstash` inside protect-ffi. The WASM entry has no filesystem and
 * no profile store, so env is the only fallback — and until now there was
 * none, which meant every edge caller had to plumb four values by hand even in
 * Deno / Node / Bun where the environment is right there.
 *
 * Two things here are worth more than the happy path:
 *
 * 1. **The `typeof process` guard.** This module is the edge entry. In a
 *    Cloudflare Worker or a browser `process` is undeclared, so a bare
 *    `process.env` read is a `ReferenceError` — a crash on client
 *    construction, not a missed lookup. `process?.env` would NOT save it;
 *    optional chaining still evaluates the identifier. The test deletes the
 *    global to reproduce that runtime honestly.
 * 2. **The keypair rule.** `CS_CLIENT_ID` / `CS_CLIENT_KEY` are filled only
 *    when BOTH are present, matching protect-ffi's native reader. Half a
 *    keypair is a misconfiguration; silently mixing one env value with one
 *    config value fails later, inside ZeroKMS, with a far less obvious error.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(() => ({ data: { __mock: 'access-key-strategy' } })),
  },
  OidcFederationStrategy: class {},
}))

vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ({
  newClient: vi.fn(),
  encrypt: vi.fn(),
  decrypt: vi.fn(),
  isEncrypted: vi.fn(),
}))

import { withEnvCredentials } from '../src/wasm-inline'

const CRN = 'crn:ap-southeast-2.aws:test-workspace'

const ENV_KEYS = [
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ACCESS_KEY',
  'CS_ACCESS_KEY',
] as const

let saved: Record<string, string | undefined>

beforeEach(() => {
  saved = Object.fromEntries(ENV_KEYS.map((k) => [k, process.env[k]]))
  for (const k of ENV_KEYS) delete process.env[k]
})

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  vi.restoreAllMocks()
})

describe('withEnvCredentials', () => {
  it('fills every credential from the environment', () => {
    process.env.CS_CLIENT_ID = 'env-id'
    process.env.CS_CLIENT_KEY = 'env-key'
    process.env.CS_WORKSPACE_CRN = CRN
    process.env.CS_CLIENT_ACCESS_KEY = 'env-access'

    expect(withEnvCredentials({} as never)).toMatchObject({
      clientId: 'env-id',
      clientKey: 'env-key',
      workspaceCrn: CRN,
      accessKey: 'env-access',
    })
  })

  it('lets an explicit config value win over the environment', () => {
    process.env.CS_CLIENT_ID = 'env-id'
    process.env.CS_CLIENT_KEY = 'env-key'
    process.env.CS_WORKSPACE_CRN = 'crn:env'
    process.env.CS_CLIENT_ACCESS_KEY = 'env-access'

    const resolved = withEnvCredentials({
      clientId: 'cfg-id',
      clientKey: 'cfg-key',
      workspaceCrn: CRN,
      accessKey: 'cfg-access',
    } as never)

    expect(resolved).toMatchObject({
      clientId: 'cfg-id',
      clientKey: 'cfg-key',
      workspaceCrn: CRN,
      accessKey: 'cfg-access',
    })
  })

  it('fills gaps without disturbing what was supplied', () => {
    process.env.CS_CLIENT_ID = 'env-id'
    process.env.CS_CLIENT_KEY = 'env-key'
    process.env.CS_WORKSPACE_CRN = CRN

    const resolved = withEnvCredentials({ accessKey: 'cfg-access' } as never)

    expect(resolved).toMatchObject({
      clientId: 'env-id',
      clientKey: 'env-key',
      workspaceCrn: CRN,
      accessKey: 'cfg-access',
    })
  })

  describe('the clientId / clientKey keypair', () => {
    it('ignores CS_CLIENT_ID when CS_CLIENT_KEY is absent', () => {
      process.env.CS_CLIENT_ID = 'env-id'

      const resolved = withEnvCredentials({} as never)

      expect(resolved.clientId).toBeUndefined()
      expect(resolved.clientKey).toBeUndefined()
    })

    it('ignores CS_CLIENT_KEY when CS_CLIENT_ID is absent', () => {
      process.env.CS_CLIENT_KEY = 'env-key'

      const resolved = withEnvCredentials({} as never)

      expect(resolved.clientId).toBeUndefined()
      expect(resolved.clientKey).toBeUndefined()
    })

    it('does not mix one env value with one config value', () => {
      // The dangerous case: a stale CS_CLIENT_ID alongside a config clientKey
      // would otherwise produce a mismatched pair that fails inside ZeroKMS.
      process.env.CS_CLIENT_ID = 'env-id'

      const resolved = withEnvCredentials({ clientKey: 'cfg-key' } as never)

      expect(resolved.clientId).toBeUndefined()
      expect(resolved.clientKey).toBe('cfg-key')
    })
  })

  describe('the access-key variable names', () => {
    it('prefers CS_CLIENT_ACCESS_KEY, the documented name', () => {
      process.env.CS_CLIENT_ACCESS_KEY = 'documented'
      process.env.CS_ACCESS_KEY = 'legacy'

      expect(withEnvCredentials({} as never).accessKey).toBe('documented')
    })

    it('accepts CS_ACCESS_KEY, which protect-ffi native reads', () => {
      process.env.CS_ACCESS_KEY = 'legacy'

      expect(withEnvCredentials({} as never).accessKey).toBe('legacy')
    })
  })

  describe('the strategy path', () => {
    it('does not fill accessKey when an authStrategy is supplied', () => {
      // `accessKey` is `never` on the strategy arm, and the two are mutually
      // exclusive — filling it from a stray env var would make
      // `resolveStrategy` reject a config the caller wrote correctly.
      process.env.CS_CLIENT_ACCESS_KEY = 'env-access'

      const resolved = withEnvCredentials({
        authStrategy: { getToken: async () => ({ data: { token: 't' } }) },
      } as never)

      expect(resolved.accessKey).toBeUndefined()
      expect(resolved.authStrategy).toBeDefined()
    })

    it('does not fill accessKey for the deprecated strategy alias either', () => {
      process.env.CS_CLIENT_ACCESS_KEY = 'env-access'

      const resolved = withEnvCredentials({
        strategy: { getToken: async () => ({ data: { token: 't' } }) },
      } as never)

      expect(resolved.accessKey).toBeUndefined()
    })

    it('still fills the client keypair, which the strategy path needs', () => {
      // The strategy authenticates; the client key still encrypts. Both paths
      // need clientId / clientKey.
      process.env.CS_CLIENT_ID = 'env-id'
      process.env.CS_CLIENT_KEY = 'env-key'

      const resolved = withEnvCredentials({
        authStrategy: { getToken: async () => ({ data: { token: 't' } }) },
      } as never)

      expect(resolved).toMatchObject({
        clientId: 'env-id',
        clientKey: 'env-key',
      })
    })
  })

  describe('runtimes with no process global', () => {
    it('returns undefined rather than throwing a ReferenceError', () => {
      // Reproduces a Cloudflare Worker / browser: `process` is not merely
      // empty, it is undeclared. A bare `process.env` read here is a crash on
      // client construction — and `process?.env` would crash identically,
      // which is why the implementation uses `typeof`.
      const originalProcess = globalThis.process
      // biome-ignore lint/performance/noDelete: assigning undefined leaves the
      // binding declared, so `typeof process` still reports "object" and the
      // guard under test is never exercised.
      delete (globalThis as { process?: unknown }).process

      try {
        expect(() => withEnvCredentials({} as never)).not.toThrow()
        expect(withEnvCredentials({} as never).clientId).toBeUndefined()
      } finally {
        globalThis.process = originalProcess
      }
    })
  })
})
