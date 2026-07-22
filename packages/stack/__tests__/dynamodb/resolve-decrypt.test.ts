/**
 * Pure unit tests for the two client-shape helpers that bridge the nominal
 * `EncryptionClient` (chainable, carries `.audit()`) and the typed client from
 * `EncryptionV3` (plain `Promise<Result>`). Both branches were previously only
 * reachable through a live ZeroKMS decrypt; these move that assurance onto the
 * pure CI lane. No credentials, no network.
 */
import { afterEach, describe, expect, it, vi } from 'vitest'
import { resolveDecryptResult, throwPreservingCode } from '@/dynamodb/helpers'
import { logger } from '@/utils/logger'

// The metadata-drop tests `vi.spyOn(logger, 'debug')` — the same shared singleton
// `helpers-v3.test.ts` also spies. Each test restores its own spy in a `finally`;
// this hook is the safety net so a patched method can never survive a test
// boundary (`restoreAllMocks` un-patches; `clearAllMocks` only clears calls).
afterEach(() => {
  vi.restoreAllMocks()
})

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

  it('returns a failure — not a silent undefined success — for a malformed result', async () => {
    // A non-conforming client that resolves to a bare value (or `{}`) has
    // neither `data` nor `failure`. Casting it straight through would surface a
    // fake success carrying `undefined`; the shape must be rejected instead.
    for (const malformed of [{}, 42, undefined]) {
      const result = await resolveDecryptResult(Promise.resolve(malformed), {})

      expect(result.failure).toBeDefined()
      expect(typeof result.failure?.message).toBe('string')
      expect(result.data).toBeUndefined()
    }
  })

  it('logs when audit metadata is dropped for a non-chainable operation', async () => {
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      await resolveDecryptResult(Promise.resolve({ data: { x: 1 } }), {
        metadata: { m: 42 },
      })

      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('audit metadata ignored'),
      )
    } finally {
      spy.mockRestore()
    }
  })

  it('does not log about audit metadata when none is passed', async () => {
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      await resolveDecryptResult(Promise.resolve({ data: { x: 1 } }), {})

      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
    }
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
