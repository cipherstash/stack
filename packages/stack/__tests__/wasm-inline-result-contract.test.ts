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
vi.mock('@cipherstash/protect-ffi/wasm-inline', () => ffi)
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
  ])('%s surfaces a %s FFI throw as { failure } typed %s', async (method, ffiName, expectedType) => {
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
  })

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
  ])('preserves the detail of %s rejection', async (_label, thrown, expected) => {
    ffi.encrypt.mockRejectedValueOnce(thrown)

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.type).toBe('EncryptionError')
    expect(result.failure?.message).toBe(expected)
    expect(result.failure?.message).not.toBe('Something went wrong')
  })

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
