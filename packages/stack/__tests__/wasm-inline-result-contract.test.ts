import { beforeEach, describe, expect, it, vi } from 'vitest'

// The WASM entry THREW on every fallible method until #741, diverging from the
// repo-wide contract in AGENTS.md ("Operations return `{ data }` or
// `{ failure }`. Preserve this shape and error `type` values in
// `EncryptionErrorTypes`."). These tests pin the aligned surface so it cannot
// drift back: every fallible method returns a Result on BOTH paths, with a
// `failure.type` drawn from `EncryptionErrorTypes` and encrypt/decrypt
// classified distinctly. `isEncrypted` stays a bare boolean — a pure predicate
// with nothing to fail at, as on the native entry.

const ffi = vi.hoisted(() => ({
  newClient: vi.fn(async () => ({ handle: 'wasm-client' })),
  encrypt: vi.fn(async () => ({ v: 3, i: {}, c: 'ct' })),
  decrypt: vi.fn(async () => 'plain'),
  isEncrypted: vi.fn(() => true),
  encryptQuery: vi.fn(async () => ({ v: 3, i: {} })),
  encryptQueryBulk: vi.fn(async () => [{ v: 3, i: {} }]),
  encryptBulk: vi.fn(async () => [{ v: 3, i: {}, c: 'ct' }]),
  decryptBulkFallible: vi.fn(async () => [{ data: 'plain' }]),
}))
vi.mock('@cipherstash/protect-ffi/wasm-inline', async (importOriginal) => ({
  // Partial, not total: `readErrorCode` validates `failure.code` against the
  // closed `ProtectErrorCode` set with the real `isProtectErrorCode`, and a
  // hand-written stand-in would let a wrong answer through.
  ...(await importOriginal<
    typeof import('@cipherstash/protect-ffi/wasm-inline')
  >()),
  ...ffi,
}))
vi.mock('@cipherstash/auth/wasm-inline', () => ({
  AccessKeyStrategy: {
    create: vi.fn(() => ({
      data: { getToken: async () => ({ token: 'test' }) },
    })),
  },
  OidcFederationStrategy: {},
}))

import { encryptedTable, types } from '../src/eql/v3'
import { Encryption } from '../src/wasm-inline'

const users = encryptedTable('users', { email: types.TextEq('email') })

async function client() {
  return Encryption({
    schemas: [users],
    config: {
      workspaceCrn: 'crn:test:ws',
      accessKey: 'test-key',
      clientId: 'id',
      clientKey: 'key',
    },
  })
}

const ct = () => ({ v: 3, i: { t: 'users', c: 'email' }, c: 'x' }) as never

describe('wasm-inline Result contract — success path', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('every fallible method resolves { data } and never a bare value', async () => {
    const c = await client()
    const opts = { table: users, column: users.email }

    const results = [
      await c.encrypt('a@b.com', opts),
      await c.decrypt(ct()),
      await c.encryptQuery('a@b.com', opts),
      await c.encryptQueryBulk([{ value: 'a@b.com', ...opts }]),
      await c.bulkEncrypt([{ plaintext: 'a@b.com', ...opts }]),
      await c.bulkDecrypt([ct()]),
    ]

    for (const r of results) {
      expect(r).toHaveProperty('data')
      expect(r.failure).toBeUndefined()
    }
  })

  it('isEncrypted stays a bare boolean — nothing to fail at', async () => {
    const c = await client()
    expect(c.isEncrypted({})).toBe(true)
  })
})

describe('wasm-inline Result contract — failure path', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  // Encrypt-side and decrypt-side failures must be distinguishable by `type`,
  // which is the whole point of carrying EncryptionErrorTypes rather than a
  // bare message.
  it.each([
    ['encrypt', 'encrypt', 'EncryptionError'],
    ['encryptQuery', 'encryptQuery', 'EncryptionError'],
    ['bulkEncrypt', 'encryptBulk', 'EncryptionError'],
    ['decrypt', 'decrypt', 'DecryptionError'],
    ['bulkDecrypt', 'decryptBulkFallible', 'DecryptionError'],
  ])(
    '%s surfaces a %s FFI throw as { failure } typed %s',
    async (method, ffiName, expectedType) => {
      ;(ffi as Record<string, ReturnType<typeof vi.fn>>)[
        ffiName
      ].mockRejectedValueOnce(new Error('ffi exploded'))

      const c = await client()
      const opts = { table: users, column: users.email }
      const call: Record<string, () => Promise<unknown>> = {
        encrypt: () => c.encrypt('a@b.com', opts),
        encryptQuery: () => c.encryptQuery('a@b.com', opts),
        bulkEncrypt: () => c.bulkEncrypt([{ plaintext: 'a@b.com', ...opts }]),
        decrypt: () => c.decrypt(ct()),
        bulkDecrypt: () => c.bulkDecrypt([ct()]),
      }

      // Resolves — it must NOT reject. That is the regression this guards.
      const result = (await call[method]()) as {
        data?: unknown
        failure?: { type: string; message: string }
      }

      expect(result.data).toBeUndefined()
      expect(result.failure).toMatchObject({
        type: expectedType,
        message: 'ffi exploded',
      })
    },
  )

  // Non-Error rejections must keep their detail. `withResult`'s default
  // `ensureError` would replace them with `new Error('Something went wrong')`,
  // discarding the value (@byteslice/result@0.2.0, `dist/result.js:27`) — so
  // this entry passes the `onException` hook, which takes precedence.
  //
  // This is not hypothetical on WASM: wasm-bindgen rejects with the raw
  // `JsValue` from Rust (`throw takeFromExternrefTable0(...)`), and the WASM
  // build exports no `ProtectError` class, so a real FFI failure can arrive as
  // a bare string or object. Losing it would be worse than the throwing
  // behaviour this entry had before, which propagated the raw value.
  it.each([
    ['a string', 'boom from rust', 'boom from rust'],
    [
      'an object',
      { code: 'EQL_X', detail: 'bad domain' },
      '{"code":"EQL_X","detail":"bad domain"}',
    ],
  ])(
    'preserves the detail of %s rejection',
    async (_label, thrown, expected) => {
      ffi.encrypt.mockRejectedValueOnce(thrown)

      const c = await client()
      const result = await c.encrypt('a@b.com', {
        table: users,
        column: users.email,
      })

      expect(result.failure?.type).toBe('EncryptionError')
      expect(result.failure?.message).toBe(expected)
      expect(result.failure?.message).not.toBe('Something went wrong')
    },
  )

  it('falls back to String() for a value JSON cannot serialize', async () => {
    // A cycle makes JSON.stringify throw; the catch must still yield a
    // well-formed failure rather than propagating a second error.
    const cyclic: Record<string, unknown> = { a: 1 }
    cyclic.self = cyclic
    ffi.encrypt.mockRejectedValueOnce(cyclic)

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.type).toBe('EncryptionError')
    expect(result.failure?.message).toBe('[object Object]')
  })
})

/**
 * `failure.code` is typed `ProtectErrorCode` — a CLOSED set, owned by
 * protect-ffi and pinned there by `errorCodes.test.ts`. Both entries have to
 * honour that or the field means one thing on Node and another on Workers.
 *
 * The native entry validates (`getErrorCode` in
 * `src/encryption/helpers/error-code.ts`) precisely because a `code` property
 * on a thrown object is not evidence of anything: Node stamps `ECONNRESET`,
 * `ENOTFOUND` and `MODULE_NOT_FOUND` onto its own errors, and on this entry a
 * rejection is whatever wasm-bindgen was handed. Reading the property without
 * checking the value republished those as encryption error codes.
 *
 * `authCode` is deliberately NOT validated, on either entry: that set belongs
 * to `@cipherstash/auth`, ships on its own release train, and is typed open so
 * a code newer than the pinned build still reaches the caller.
 */
describe('wasm-inline failure.code is the closed protect-ffi set', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  async function codeFrom(rejection: unknown) {
    ffi.encrypt.mockRejectedValueOnce(rejection)
    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })
    return result.failure?.code
  }

  it.each([
    ['a real protect-ffi code', 'UNKNOWN_COLUMN'],
    ['another one', 'INVALID_CIPHERTEXT'],
  ])('keeps %s', async (_label, code) => {
    expect(await codeFrom(Object.assign(new Error('boom'), { code }))).toBe(
      code,
    )
  })

  it.each([
    ["Node's socket errors", 'ECONNRESET'],
    ['a module resolution failure', 'MODULE_NOT_FOUND'],
    ['anything else wearing a code', 'EQL_X'],
  ])('drops %s, exactly as the native entry does', async (_label, code) => {
    expect(
      await codeFrom(Object.assign(new Error('boom'), { code })),
    ).toBeUndefined()
  })

  it('drops an unrecognised code off a bare-object rejection too', async () => {
    // The path `carryDiagnostics` widened: every own key of an arbitrary
    // rejection now reaches the failure mapper, so more foreign `code`
    // properties arrive here than before.
    expect(
      await codeFrom({ error: 'boom', code: 'ECONNRESET' }),
    ).toBeUndefined()
  })

  it('leaves authCode open — a code newer than this build still lands', async () => {
    ffi.encrypt.mockRejectedValueOnce(
      Object.assign(new Error('boom'), {
        code: 'ECONNRESET',
        authCode: 'SOME_FUTURE_AUTH_CODE',
      }),
    )

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.code).toBeUndefined()
    expect(result.failure?.authCode).toBe('SOME_FUTURE_AUTH_CODE')
  })
})
