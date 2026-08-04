import { describe, expect, it } from 'vitest'
import { withEnvCredentials } from './credentials.js'
import type { CredentialOpts, EnvReader } from './credentials.js'

function makeEnv(vars: Record<string, string>): EnvReader {
  return (key) => vars[key]
}

const emptyEnv = makeEnv({})

describe('withEnvCredentials', () => {
  it('returns env values when no opts are provided', () => {
    const env = makeEnv({
      CS_CLIENT_ID: 'env-id',
      CS_CLIENT_KEY: 'env-key',
      CS_WORKSPACE_CRN: 'env-crn',
      CS_ACCESS_KEY: 'env-access',
    })

    const result = withEnvCredentials(undefined, env)

    expect(result).toEqual({
      clientId: 'env-id',
      clientKey: 'env-key',
      workspaceCrn: 'env-crn',
      accessKey: 'env-access',
    })
  })

  it('explicit opts take precedence over env vars', () => {
    const env = makeEnv({
      CS_CLIENT_ID: 'env-id',
      CS_CLIENT_KEY: 'env-key',
      CS_WORKSPACE_CRN: 'env-crn',
      CS_ACCESS_KEY: 'env-access',
    })

    const result = withEnvCredentials(
      {
        clientId: 'opt-id',
        clientKey: 'opt-key',
        workspaceCrn: 'opt-crn',
        accessKey: 'opt-access',
      },
      env,
    )

    expect(result).toEqual({
      clientId: 'opt-id',
      clientKey: 'opt-key',
      workspaceCrn: 'opt-crn',
      accessKey: 'opt-access',
    })
  })

  describe('clientId/clientKey atomic pair', () => {
    it('uses both env values when both CS_CLIENT_ID and CS_CLIENT_KEY are set', () => {
      const env = makeEnv({
        CS_CLIENT_ID: 'env-id',
        CS_CLIENT_KEY: 'env-key',
      })

      const result = withEnvCredentials(undefined, env)

      expect(result.clientId).toBe('env-id')
      expect(result.clientKey).toBe('env-key')
    })

    it('uses neither env value when only CS_CLIENT_ID is set', () => {
      const env = makeEnv({ CS_CLIENT_ID: 'env-id' })

      const result = withEnvCredentials(undefined, env)

      expect(result.clientId).toBeUndefined()
      expect(result.clientKey).toBeUndefined()
    })

    it('uses neither env value when only CS_CLIENT_KEY is set', () => {
      const env = makeEnv({ CS_CLIENT_KEY: 'env-key' })

      const result = withEnvCredentials(undefined, env)

      expect(result.clientId).toBeUndefined()
      expect(result.clientKey).toBeUndefined()
    })

    it('uses neither env value when neither is set', () => {
      const result = withEnvCredentials(undefined, emptyEnv)

      expect(result.clientId).toBeUndefined()
      expect(result.clientKey).toBeUndefined()
    })
  })

  describe('workspaceCrn and accessKey are independent', () => {
    it('fills workspaceCrn from env independently', () => {
      const env = makeEnv({ CS_WORKSPACE_CRN: 'env-crn' })

      const result = withEnvCredentials(undefined, env)

      expect(result.workspaceCrn).toBe('env-crn')
    })

    it('fills accessKey from env independently', () => {
      const env = makeEnv({ CS_ACCESS_KEY: 'env-access' })

      const result = withEnvCredentials(undefined, env)

      expect(result.accessKey).toBe('env-access')
    })
  })

  it('preserves extra properties on the opts object', () => {
    const result = withEnvCredentials(
      {
        clientId: 'opt-id',
        clientKey: 'opt-key',
        name: 'my-keyset',
      },
      emptyEnv,
    )

    expect(result.name).toBe('my-keyset')
    expect(result.clientId).toBe('opt-id')
  })

  it('partial opts filled from env for non-keypair fields', () => {
    const env = makeEnv({
      CS_CLIENT_ID: 'env-id',
      CS_CLIENT_KEY: 'env-key',
      CS_WORKSPACE_CRN: 'env-crn',
      CS_ACCESS_KEY: 'env-access',
    })

    const opts: CredentialOpts = { accessKey: 'opt-access' }
    const result = withEnvCredentials(opts, env)

    expect(result.clientId).toBe('env-id')
    expect(result.clientKey).toBe('env-key')
    expect(result.workspaceCrn).toBe('env-crn')
    expect(result.accessKey).toBe('opt-access')
  })
})
