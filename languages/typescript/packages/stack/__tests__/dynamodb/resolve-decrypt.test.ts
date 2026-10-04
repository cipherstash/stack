/**
 * Pure unit tests for the client-shape helpers behind the DynamoDB adapter's
 * decrypt AND encrypt paths.
 *
 * On decrypt, both native clients — nominal `EncryptionClient` and the typed EQL
 * v3 client (whose decrypt returns a `MappedDecryptOperation`) — are chainable
 * and carry `.audit()`; the bare-promise branch is taken by the wasm-inline
 * client and by a non-conforming custom one.
 *
 * The same split exists on encrypt, and only the decrypt half handled it: the
 * encrypt operations chained `.audit()` unconditionally, so the wasm-inline
 * client failed every write (#788 review follow-up). `resolveEncryptResult` is
 * the mirror, and the chainable half of its coverage matters most — the native
 * clients' encrypt audit trail has no other credential-free test.
 *
 * `throwPreservingCode` and `handleError` are the two ends of the same seam —
 * the first exists only so the FFI error code survives `withResult`'s wrapping
 * long enough for the second to read it back off the rethrown Error — so they
 * are covered here too.
 *
 * Every branch was previously reachable only through live ZeroKMS; these move
 * that assurance onto the pure CI lane. No credentials, no network.
 */
import type { Result } from '@byteslice/result'
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  type MockInstance,
  vi,
} from 'vitest'
import {
  handleError,
  resolveDecryptResult,
  resolveEncryptResult,
  throwPreservingCode,
} from '@/dynamodb/helpers'
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
    // `null` and `[]` pin the two clauses that are otherwise untested: without
    // the `resolved === null` guard, `'data' in null` throws a TypeError, and an
    // array passes `typeof === 'object'` so it must be rejected on the key checks.
    for (const malformed of [{}, 42, undefined, null, []]) {
      const result = await resolveDecryptResult(Promise.resolve(malformed), {})

      expect(result.failure?.message).toMatch(/malformed result/)
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

/**
 * The write-path mirror (#788 review follow-up). The encrypt operations used
 * to chain `.audit()` unconditionally, so a client returning a bare promise
 * (the wasm-inline entry) failed every encrypt with
 * `.audit is not a function`. These pin BOTH directions: the chainable path
 * must still forward metadata — the native clients' audit trail depends on it,
 * and its only other coverage is a live-credential suite — and the bare path
 * must resolve instead of throwing.
 */
describe('resolveEncryptResult', () => {
  /**
   * The NATIVE shape, not a hand-rolled lookalike.
   *
   * `EncryptionOperation.audit()` returns `this` and the operation is a thenable
   * whose `then()` calls `execute()` — so the metadata is read back out of the
   * operation at execution time, not passed forward as an argument. A stub whose
   * `audit()` returns a promise satisfies the helper while testing none of that:
   * break `audit()` so it stops recording, or break `then()` so it never
   * executes, and such a stub still passes while every native encrypt loses its
   * audit trail. Subclass the real base class instead, exactly as the decrypt
   * half of this file does with `MappedDecryptOperation`.
   */
  it('forwards metadata into a real native operation and executes it once', async () => {
    let seenMetadata: Record<string, unknown> | undefined
    let executions = 0

    class NativeEncrypt extends EncryptionOperation<{ encrypted: boolean }> {
      override async execute(): Promise<
        Result<{ encrypted: boolean }, EncryptionError>
      > {
        executions += 1
        seenMetadata = this.getAuditData().metadata
        return { data: { encrypted: true } }
      }
    }

    const result = await resolveEncryptResult(
      new NativeEncrypt(),
      { metadata: { sub: 'u1' } },
      'encryptModel',
    )

    expect(result).toEqual({ data: { encrypted: true } })
    // The metadata reached `execute()` — the only place it can reach ZeroKMS.
    expect(seenMetadata).toEqual({ sub: 'u1' })
    // Awaiting a thenable that `.audit()` returned as `this` must not run it twice.
    expect(executions).toBe(1)
  })

  it('propagates a native operation failure without unwrapping it', async () => {
    class FailingEncrypt extends EncryptionOperation<{ encrypted: boolean }> {
      override async execute(): Promise<
        Result<{ encrypted: boolean }, EncryptionError>
      > {
        return {
          failure: {
            type: EncryptionErrorTypes.EncryptionError,
            message: 'ffi exploded',
          },
        }
      }
    }

    const result = await resolveEncryptResult(
      new FailingEncrypt(),
      { metadata: { sub: 'u1' } },
      'encryptModel',
    )

    expect(result.failure?.message).toBe('ffi exploded')
    expect(result.data).toBeUndefined()
  })

  it('awaits a bare promise instead of throwing (wasm-inline encrypt)', async () => {
    const result = await resolveEncryptResult(
      Promise.resolve({ data: { encrypted: true } }),
      { metadata: { dropped: true } },
      'encryptModel',
    )

    expect(result).toEqual({ data: { encrypted: true } })
  })

  it('propagates a failure result unchanged', async () => {
    const failure = { failure: { message: 'boom', code: 'X' } }

    await expect(
      resolveEncryptResult(Promise.resolve(failure), {}, 'bulkEncryptModels'),
    ).resolves.toEqual(failure)
  })

  it('returns a failure — not a fake success — for a malformed result', async () => {
    // Fail closed on every non-Result shape. `null` and `[]` are here
    // deliberately: `null` is what makes the `resolved === null` clause
    // load-bearing (without it, `'data' in null` throws a TypeError rather than
    // returning the intended message), and `typeof [] === 'object'` means an
    // array reaches the property checks and must still be rejected.
    for (const malformed of [{}, 42, undefined, null, []]) {
      const result = await resolveEncryptResult(
        Promise.resolve(malformed),
        {},
        'encryptModel',
      )

      expect(result.failure?.message).toMatch(/malformed result/)
      expect(result.data).toBeUndefined()
    }
  })

  it('names the operation in the dropped-metadata log, and stays silent without metadata', async () => {
    const spy = vi.spyOn(logger, 'debug').mockImplementation(() => {})

    try {
      await resolveEncryptResult(
        Promise.resolve({ data: {} }),
        { metadata: { m: 1 } },
        'bulkEncryptModels',
      )
      expect(spy).toHaveBeenCalledWith(
        expect.stringContaining('bulkEncryptModels audit metadata ignored'),
      )

      spy.mockClear()
      await resolveEncryptResult(
        Promise.resolve({ data: {} }),
        {},
        'encryptModel',
      )
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

/**
 * The adapter's error funnel — every operation's `catch` ends here, and the
 * code it stamps on the way out is what a caller branches on.
 *
 * protect-ffi 0.31.0 removed the `ProtectError` class `handleError`'s first
 * branch matched with `instanceof`, collapsing the two branches into one — and
 * the collapse fixed a bug. The old fallback accepted ANY string-valued `code`
 * and asserted it into `ProtectErrorCode`, so a Node error arriving from the
 * DynamoDB client (`ECONNRESET` on a dropped socket) was handed back as an
 * encryption error code, and a caller keying retry-vs-fail off `error.code`
 * read a transport fault as a crypto fault. `isProtectErrorCode` checks the
 * value against the known set.
 *
 * That fix had no test of its own: the predicate was covered directly
 * (`error-codes.test.ts`), but its use here — the whole point — was reachable
 * only through live ZeroKMS. These pin it credential-free.
 */
describe('handleError', () => {
  let errorLog: MockInstance

  beforeEach(() => {
    // `handleError` always calls the shared logger at `error` level, which the
    // default `STASH_STACK_LOG` emits. Silence it so the reporter stays clean.
    // The outer `afterEach` un-patches.
    errorLog = vi.spyOn(logger, 'error').mockImplementation(() => {})
  })

  it('does not surface a foreign error code as an encryption error code', () => {
    const error = handleError(
      { code: 'ECONNRESET', message: 'socket hang up' },
      'decryptModel',
    )

    expect(error.code).toBe('DYNAMODB_ENCRYPTION_ERROR')
    expect(error.name).toBe('EncryptedDynamoDBError')
    expect(error.details).toEqual({ context: 'decryptModel' })
  })

  it('preserves a code the FFI actually emits', () => {
    // `UNKNOWN_COLUMN` is a real member of `PROTECT_ERROR_CODES` in
    // protect-ffi 0.31.0 — a code the caller is meant to branch on, so the
    // guard must not flatten it into the generic one.
    const error = handleError(
      { code: 'UNKNOWN_COLUMN', message: 'no such column' },
      'encryptModel',
    )

    expect(error.code).toBe('UNKNOWN_COLUMN')
  })

  it('falls back to the generic code when there is no usable code at all', () => {
    for (const raw of [
      {},
      new Error('plain'),
      { code: 42 },
      { code: null },
      'a bare string',
    ]) {
      expect(handleError(raw, 'decryptModel').code).toBe(
        'DYNAMODB_ENCRYPTION_ERROR',
      )
    }
  })

  it('survives the round trip a real failure takes through throwPreservingCode', () => {
    // The production path: an operation's `{ failure }` is rethrown by
    // `throwPreservingCode` as an Error carrying `code`, `withResult` catches
    // it, and `handleError` reads the code back. Both codes must come out the
    // far side classified the same way they went in.
    const rethrow = (code: string) => {
      try {
        throwPreservingCode({ message: 'boom', code })
      } catch (error) {
        return handleError(error, 'bulkDecryptModels')
      }
      return expect.unreachable('should have thrown')
    }

    expect(rethrow('UNKNOWN_COLUMN').code).toBe('UNKNOWN_COLUMN')
    expect(rethrow('ECONNRESET').code).toBe('DYNAMODB_ENCRYPTION_ERROR')
  })

  it('extracts the message from an Error, a plain object, or anything else', () => {
    expect(
      handleError(new Error('from an Error'), 'decryptModel').message,
    ).toBe('from an Error')
    expect(
      handleError({ message: 'from an object' }, 'decryptModel').message,
    ).toBe('from an object')
    // A non-string `message` is not a message; fall through to `String(error)`.
    expect(handleError({ message: 42 }, 'decryptModel').message).toBe(
      '[object Object]',
    )
    expect(handleError('bare string', 'decryptModel').message).toBe(
      'bare string',
    )
    expect(handleError(null, 'decryptModel').message).toBe('null')
  })

  it('hands the constructed error to both the errorHandler and the caller logger', () => {
    const seen: unknown[] = []
    const callerLog = { error: vi.fn() }

    const error = handleError(
      { code: 'ECONNRESET', message: 'socket hang up' },
      'decryptModel',
      { errorHandler: (e) => seen.push(e), logger: callerLog },
    )

    // Identity, not structural equality: the handler must receive the SAME
    // object the caller gets back, so a handler reading `.code` sees the
    // classified one.
    expect(seen).toHaveLength(1)
    expect(seen[0]).toBe(error)
    expect(callerLog.error).toHaveBeenCalledWith('Error in decryptModel', error)
    expect(errorLog).toHaveBeenCalledWith(
      expect.stringContaining('DynamoDB error in decryptModel'),
    )
  })
})
