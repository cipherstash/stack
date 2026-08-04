import { afterEach, describe, expect, it } from 'vitest'
import { newClientArgs } from './newClientArgs.js'
import type { AuthStrategy, EncryptConfig } from './types.js'

const encryptConfig: EncryptConfig = { v: 1, tables: {} }
const authStrategy: AuthStrategy = { getToken: async () => ({ token: 'new' }) }
const legacyStrategy: AuthStrategy = {
  getToken: async () => ({ token: 'old' }),
}

describe('newClientArgs', () => {
  afterEach(() => {
    for (const key of [
      'CS_CLIENT_ID',
      'CS_CLIENT_KEY',
      'CS_WORKSPACE_CRN',
      'CS_ACCESS_KEY',
    ]) {
      delete process.env[key]
    }
  })

  describe('strategy selection', () => {
    it('passes authStrategy through as the second argument', () => {
      const [, strategy] = newClientArgs({ encryptConfig, authStrategy })
      expect(strategy).toBe(authStrategy)
    })

    it('still honours the deprecated `strategy` name', () => {
      const [, strategy] = newClientArgs({
        encryptConfig,
        strategy: legacyStrategy,
      })
      expect(strategy).toBe(legacyStrategy)
    })

    it('prefers authStrategy when both names are set', () => {
      // A rename is only safe if the new name wins. Otherwise a caller
      // mid-migration who sets both silently keeps the old object.
      const [, strategy] = newClientArgs({
        encryptConfig,
        authStrategy,
        strategy: legacyStrategy,
      })
      expect(strategy).toBe(authStrategy)
    })

    it('yields undefined when neither is set', () => {
      // Not an error since #142: the Rust falls through to
      // `CredentialOpts::build_strategy()`, which resolves an
      // `AccessKeyStrategy` from `clientOpts`.
      const [, strategy] = newClientArgs({ encryptConfig })
      expect(strategy).toBeUndefined()
    })
  })

  describe('the options object', () => {
    it('never carries the strategy', () => {
      // It would not survive the trip: neon's `Json` extractor stringifies,
      // and JSON.stringify drops functions. The addon takes it as a separate
      // `Root<JsObject>` argument for exactly that reason.
      const [opts] = newClientArgs({
        encryptConfig,
        authStrategy,
        strategy: legacyStrategy,
      })
      expect(opts).not.toHaveProperty('authStrategy')
      expect(opts).not.toHaveProperty('strategy')
    })

    it('carries only the three fields the Rust deserializes', () => {
      const [opts] = newClientArgs({ encryptConfig, eqlVersion: 3 })
      expect(Object.keys(opts).sort()).toEqual([
        'clientOpts',
        'encryptConfig',
        'eqlVersion',
      ])
      expect(opts.encryptConfig).toBe(encryptConfig)
      expect(opts.eqlVersion).toBe(3)
    })

    it('fills credentials from the environment', () => {
      // Read on the JS side and passed through as explicit fields — the Rust
      // cannot read env on either target (Bun on Neon, no env at all on wasm).
      process.env.CS_CLIENT_ID = 'env-id'
      process.env.CS_CLIENT_KEY = 'env-key'
      const [opts] = newClientArgs({ encryptConfig })
      expect(opts.clientOpts).toMatchObject({
        clientId: 'env-id',
        clientKey: 'env-key',
      })
    })

    it('lets explicit credentials win over the environment', () => {
      process.env.CS_CLIENT_ID = 'env-id'
      process.env.CS_CLIENT_KEY = 'env-key'
      const [opts] = newClientArgs({
        encryptConfig,
        clientOpts: { clientId: 'explicit-id', clientKey: 'explicit-key' },
      })
      expect(opts.clientOpts).toMatchObject({
        clientId: 'explicit-id',
        clientKey: 'explicit-key',
      })
    })

    it('forwards a key the Rust does not declare, for serde to reject', () => {
      // The point of #144 on this binding: `newClient` used to rebuild the
      // native options field by field, which dropped anything it didn't name
      // before the Rust could complain.
      const [opts] = newClientArgs({
        encryptConfig,
        eqlVerison: 3,
      } as unknown as Parameters<typeof newClientArgs>[0])
      expect(opts).toMatchObject({ eqlVerison: 3 })
    })

    it('names the forwarded key JSON.stringify cannot carry', () => {
      // Forwarding means an unknown key now reaches neon's `Json` extractor,
      // and a circular value throws there before serde can name it. Left
      // alone the caller gets a bare "Converting circular structure to JSON".
      const logger: Record<string, unknown> = {}
      logger.self = logger
      expect(() =>
        newClientArgs({
          encryptConfig,
          logger,
        } as unknown as Parameters<typeof newClientArgs>[0]),
      ).toThrow(/newClient option `logger` cannot be sent to the addon/)

      expect(() =>
        newClientArgs({
          encryptConfig,
          requestId: 1n,
        } as unknown as Parameters<typeof newClientArgs>[0]),
      ).toThrow(/newClient option `requestId` cannot be sent to the addon/)
    })

    it('keeps keyset alongside the credentials', () => {
      // `keyset` moved under `clientOpts` on the wasm entry in #142; this is
      // the Neon side of the same shape, and the env merge must not drop it.
      const [opts] = newClientArgs({
        encryptConfig,
        clientOpts: { keyset: { Name: 'prod' } },
      })
      expect(opts.clientOpts?.keyset).toEqual({ Name: 'prod' })
    })
  })
})
