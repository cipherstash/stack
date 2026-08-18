import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const mockConnect = vi.fn()
const mockEnd = vi.fn()

vi.mock('pg', () => ({
  default: {
    Client: vi.fn(() => {
      const client: Record<string, unknown> = {
        connect: (...args: unknown[]) => mockConnect(...args),
        end: mockEnd,
      }
      return client
    }),
  },
}))

describe('createPgClient connect wrapping', () => {
  beforeEach(() => vi.clearAllMocks())
  afterEach(() => vi.restoreAllMocks())

  it('re-throws certificate failures as TlsVerificationError with the remedy', async () => {
    mockConnect.mockRejectedValue(
      Object.assign(new Error('self-signed certificate in certificate chain'), {
        code: 'SELF_SIGNED_CERT_IN_CHAIN',
      }),
    )
    const { createPgClient, TlsVerificationError } = await import(
      '../client.js'
    )
    const client = createPgClient(
      'postgres://u@aws-0-us-east-1.pooler.supabase.com/postgres?sslmode=require',
    )
    const failure = await client.connect().catch((error: unknown) => error)
    expect(failure).toBeInstanceOf(TlsVerificationError)
    expect((failure as Error).message).toContain(
      'aws-0-us-east-1.pooler.supabase.com',
    )
    expect((failure as Error).message).toContain('sslrootcert=')
    expect((failure as Error).message).toContain(
      'Never set NODE_TLS_REJECT_UNAUTHORIZED=0',
    )
  })

  it('passes non-TLS connect failures through untouched', async () => {
    const original = new Error('password authentication failed for user "u"')
    mockConnect.mockRejectedValue(original)
    const { createPgClient } = await import('../client.js')
    const client = createPgClient('postgres://u@h/app?sslmode=require')
    await expect(client.connect()).rejects.toBe(original)
  })

  it('resolves normally when connect succeeds', async () => {
    mockConnect.mockResolvedValue(undefined)
    const { createPgClient } = await import('../client.js')
    const client = createPgClient('postgres://u@h/app')
    await expect(client.connect()).resolves.toBeUndefined()
  })
})
