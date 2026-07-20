/**
 * Pure unit tests for the two client-shape helpers that bridge the nominal
 * `EncryptionClient` (chainable, carries `.audit()`) and the typed client from
 * `EncryptionV3` (plain `Promise<Result>`). Both branches were previously only
 * reachable through a live ZeroKMS decrypt; these move that assurance onto the
 * pure CI lane. No credentials, no network.
 */
import { describe, expect, it } from 'vitest'
import { resolveDecryptResult, throwPreservingCode } from '@/dynamodb/helpers'

describe('resolveDecryptResult', () => {
  it('awaits a plain promise when the operation has no .audit (typed client)', async () => {
    const result = await resolveDecryptResult(
      Promise.resolve({ data: { x: 1 } }),
      { metadata: { ignored: true } },
    )

    expect(result).toEqual({ data: { x: 1 } })
  })

  it('chains .audit and forwards metadata when present (nominal client)', async () => {
    let seen: unknown
    const operation = {
      audit(config: { metadata?: Record<string, unknown> }) {
        seen = config.metadata
        return Promise.resolve({ data: { y: 2 } })
      },
    }

    const result = await resolveDecryptResult(operation, {
      metadata: { m: 42 },
    })

    expect(result).toEqual({ data: { y: 2 } })
    expect(seen).toEqual({ m: 42 })
  })

  it('propagates a failure result unchanged', async () => {
    const failure = { failure: { message: 'boom', code: 'X' } }

    await expect(
      resolveDecryptResult(Promise.resolve(failure), { metadata: {} }),
    ).resolves.toEqual(failure)
  })
})

describe('throwPreservingCode', () => {
  it('rethrows as an Error carrying the FFI code', () => {
    try {
      throwPreservingCode({ message: 'boom', code: 'UNKNOWN_COLUMN' })
      expect.unreachable('should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(Error)
      expect((error as Error).message).toBe('boom')
      expect((error as { code?: string }).code).toBe('UNKNOWN_COLUMN')
    }
  })

  it('tolerates a missing code', () => {
    try {
      throwPreservingCode({ message: 'boom' })
      expect.unreachable('should have thrown')
    } catch (error) {
      expect((error as { code?: string }).code).toBeUndefined()
    }
  })
})
