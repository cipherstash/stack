import { describe, expect, it, vi } from 'vitest'

// The full cipherstashFromStack path calls Encryption({ schemas }), which talks to
// ZeroKMS. Mock it to a minimal client so we can assert the wiring (both v2 + v3
// middlewares returned over the same sdk). createCipherstashSdk builds a registry
// from the schemas and does not call client methods at construction, so {} suffices.
vi.mock('@cipherstash/stack', async (importOriginal) => {
  const orig = (await importOriginal()) as Record<string, unknown>
  return { ...orig, Encryption: vi.fn(async () => ({})) }
})

import { CIPHERSTASH_STRING_V3_CODEC_ID } from '../../src/extension-metadata/constants'
import { cipherstashFromStack } from '../../src/stack/from-stack'

describe('cipherstashFromStack (v3)', () => {
  it('returns BOTH bulkEncryptMiddleware and bulkEncryptV3Middleware over the same sdk', async () => {
    const contractJson = {
      storage: {
        tables: {
          user_v3: {
            columns: {
              email: { codecId: CIPHERSTASH_STRING_V3_CODEC_ID, typeParams: { index: 'equality' } },
            },
          },
        },
      },
    }
    const result = await cipherstashFromStack({ contractJson })
    const names = result.middleware.map((m) => m.name)
    expect(names).toContain('cipherstash.bulk-encrypt')
    expect(names).toContain('cipherstash.bulk-encrypt-v3')
    expect(result.extensions).toHaveLength(1)
  })
})
