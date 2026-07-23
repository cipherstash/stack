/**
 * Pure unit tests for the two client-shape helpers behind the DynamoDB adapter's
 * decrypt path. Both shipped clients — nominal `EncryptionClient` and the typed
 * EQL v3 client (whose decrypt returns a `MappedDecryptOperation`) — are
 * chainable and carry `.audit()`; the bare-promise branch remains only for a
 * non-conforming custom client. Every branch was previously reachable only
 * through a live ZeroKMS decrypt; these move that assurance onto the pure CI
 * lane. No credentials, no network.
 */
import type { Result } from '@byteslice/result'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { resolveDecryptResult, throwPreservingCode } from '@/dynamodb/helpers'
import { EncryptionOperation } from '@/encryption/operations/base-operation'
import { MappedDecryptOperation } from '@/encryption/operations/mapped-decrypt'
import { type EncryptionError, EncryptionErrorTypes } from '@/errors'
import { logger } from '@/utils/logger'

// The metadata-drop tests `vi.spyOn(logger, 'debug')` — the same shared singleton
// `helpers-v3.test.ts` also spies. Each test restores its own spy in a `finally`;
// this hook is the safety net so a patched method can never survive a test
// boundary (`restoreAllMocks` un-patches; `clearAllMocks` only clears calls).
afterEach(() => {
  vi.restoreAllMocks()
})

describe('resolveDecryptResult', () => {
  it('awaits a plain promise when the operation has no .audit (custom client)', async () => {
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

  it('does not blame the typed client in the dropped-metadata message', async () => {
    // Both shipped clients now carry `.audit()` on decrypt, so this branch is
    // reachable only from a non-conforming custom client. The message used to
    // tell the reader to switch to `Encryption({ config: { eqlVersion: 3 } })`
    // for audited decrypts, which is no longer true of any shipped client.
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      await resolveDecryptResult(Promise.resolve({ data: { x: 1 } }), {
        metadata: { m: 42 },
      })

      const message = spy.mock.calls.at(-1)?.[0] as string
      expect(message).not.toMatch(/eqlVersion/)
      expect(message).not.toMatch(/EncryptionV3/)
      expect(message).not.toMatch(/typed client/)
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

  it('forwards audit metadata through a MappedDecryptOperation and applies its map', async () => {
    // The typed EQL v3 client returns a `MappedDecryptOperation` on decrypt.
    // resolveDecryptResult sees its `.audit()` and chains it; the wrapper
    // forwards the metadata to the underlying op (whose `execute` reads it) and
    // maps the successful result. This is the DynamoDB half of acceptance #2b.
    let seenMetadata: Record<string, unknown> | undefined
    class Underlying extends EncryptionOperation<{ v: number }> {
      override async execute(): Promise<
        Result<{ v: number }, EncryptionError>
      > {
        seenMetadata = this.getAuditData().metadata
        return { data: { v: 1 } }
      }
    }

    const mapped = new MappedDecryptOperation<
      { v: number },
      { mapped: number }
    >(new Underlying(), (value) => ({ mapped: value.v + 1 }), {
      failure: {
        type: EncryptionErrorTypes.DecryptionError,
        message: 'unknown table',
      },
    })

    const result = await resolveDecryptResult(mapped, { metadata: { m: 7 } })

    expect(result).toEqual({ data: { mapped: 2 } })
    expect(seenMetadata).toEqual({ m: 7 })
  })

  it('returns the precomputed failure from a MappedDecryptOperation with no map (unknown table)', async () => {
    class Underlying extends EncryptionOperation<{ v: number }> {
      override async execute(): Promise<
        Result<{ v: number }, EncryptionError>
      > {
        return { data: { v: 1 } }
      }
    }

    const unknownTableFailure = {
      failure: {
        type: EncryptionErrorTypes.DecryptionError,
        message: 'unknown table',
      },
    }
    const mapped = new MappedDecryptOperation<
      { v: number },
      { mapped: number }
    >(new Underlying(), undefined, unknownTableFailure)

    const result = await resolveDecryptResult(mapped, { metadata: { m: 7 } })

    expect(result.failure?.message).toBe('unknown table')
    expect(result.data).toBeUndefined()
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
