import { newClient } from '@cipherstash/protect-ffi'
import { describe, expect, test } from 'vitest'

async function createClientWithUnsupportedConfig(): Promise<unknown> {
  return newClient({
    encryptConfig: {
      v: 2,
      tables: {
        users: { email: { cast_as: 'text', indexes: { unique: {} } } },
      },
    },
  })
}

describe('native error diagnostics', () => {
  test('preserves the diagnostic and JavaScript call site', async () => {
    try {
      await createClientWithUnsupportedConfig()
    } catch (error) {
      expect(error).toBeInstanceOf(Error)
      expect(error).toMatchObject({
        code: 'UNSUPPORTED_CONFIG_VERSION',
        message: 'unsupported config version: 2 (expected 1)',
      })
      expect((error as Error).stack).toContain(
        'createClientWithUnsupportedConfig',
      )
      return
    }

    throw new Error('expected newClient to reject')
  })
})
