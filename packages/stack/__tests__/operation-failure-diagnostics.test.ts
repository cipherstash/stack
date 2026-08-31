/**
 * What a failed operation carries besides its message.
 *
 * `message` preserves the upstream diagnosis. These are what a program acts
 * on — and until now an operation failure carried only two of the four: the
 * mappers enumerated `code` and `authCode` by hand, so `help` and `url` reached
 * callers by no path at all. A field the bindings populate and the SDK drops is worse
 * than one that does not exist, because it reads as supported.
 *
 * `Encryption()` (which throws) already carried all four via
 * `initDiagnostics`; this is the returned-`Result` half of the same contract.
 *
 * Credential-free: protect-ffi is mocked. `isProtectErrorCode` is deliberately
 * left REAL — `code` is a closed set, and stubbing its validator would let a
 * widened set pass unnoticed.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

/** A protect-ffi-shaped encrypted payload, so model ops detect the field. */
const enc = () => ({ v: 2, i: { t: 'users', c: 'email' }, c: 'ciphertext' })

/**
 * The full diagnostic protect-ffi throws: the `Display` message, its own
 * `ProtectErrorCode`, and `miette`'s `help` / `url`, neither of which is part
 * of `Display` and so reach JS only as fields.
 *
 * Same fixture the init-path suite uses, so the two halves of the contract are
 * demonstrably the same shape.
 */
const fullDiagnostic = () =>
  Object.assign(new Error('encrypt config is invalid'), {
    code: 'UNSUPPORTED_CONFIG_VERSION',
    help: 'Regenerate the config with a supported version.',
    url: 'https://cipherstash.com/docs/errors/unsupported-config-version',
  })

/**
 * What the mocked binding rejects with. Swapped per test.
 *
 * Held in a `vi.hoisted` box because the `vi.mock` factory below is hoisted
 * above every top-level binding in this file — a plain `let` is unreachable
 * from inside it.
 */
const mockState = vi.hoisted(() => ({
  rejection: (): unknown => new Error('rejection not set'),
}))

vi.mock('@cipherstash/protect-ffi', async (importOriginal) => {
  const rejects = async () => {
    throw mockState.rejection()
  }
  return {
    ...(await importOriginal<typeof import('@cipherstash/protect-ffi')>()),
    newClient: async () => ({ __mock: 'client' }),
    encrypt: rejects,
    decrypt: rejects,
    encryptBulk: rejects,
    decryptBulk: rejects,
    decryptBulkFallible: rejects,
    encryptQuery: rejects,
    encryptQueryBulk: rejects,
  }
})

import type { EncryptionClient } from '@/encryption'
import { encryptedTable, types } from '@/eql/v3'
import { Encryption } from '@/index'

const users = encryptedTable('users', { email: types.TextEq('email') })

const LOCK_CONTEXT = { identityClaim: ['sub'] }

/**
 * One entry per operation module under `encryption/operations/`. Each is run
 * twice — plain and `.withLockContext()` — because every one of those modules
 * carries TWO failure mappers (the operation and its lock-context sibling),
 * and a change applied to one and not the other is exactly the drift this
 * pins.
 */
const OPERATIONS: ReadonlyArray<
  // biome-ignore lint/suspicious/noExplicitAny: exercising the chainable builders
  readonly [string, (client: EncryptionClient) => any]
> = [
  [
    'encrypt',
    (c) => c.encrypt('a@b.com', { column: users.email, table: users }),
  ],
  ['decrypt', (c) => c.decrypt(enc())],
  [
    'bulkEncrypt',
    (c) =>
      c.bulkEncrypt([{ id: '1', plaintext: 'a@b.com' }], {
        column: users.email,
        table: users,
      }),
  ],
  ['bulkDecrypt', (c) => c.bulkDecrypt([{ id: '1', data: enc() }])],
  ['encryptModel', (c) => c.encryptModel({ id: '1', email: 'a@b.com' }, users)],
  ['decryptModel', (c) => c.decryptModel({ id: '1', email: enc() })],
  [
    'bulkEncryptModels',
    (c) => c.bulkEncryptModels([{ id: '1', email: 'a@b.com' }], users),
  ],
  [
    'bulkDecryptModels',
    (c) => c.bulkDecryptModels([{ id: '1', email: enc() }]),
  ],
  [
    'encryptQuery',
    (c) => c.encryptQuery('a@b.com', { column: users.email, table: users }),
  ],
  [
    'encryptQuery (batch)',
    (c) =>
      c.encryptQuery([{ value: 'a@b.com', column: users.email, table: users }]),
  ],
]

let client: EncryptionClient

beforeEach(async () => {
  mockState.rejection = fullDiagnostic
  process.env.CS_WORKSPACE_CRN = 'crn:ap-southeast-2.aws:test-workspace'
  client = await Encryption({ schemas: [users] })
})

describe('every operation failure carries the whole diagnostic', () => {
  for (const [name, run] of OPERATIONS) {
    it(`${name} carries code, help and url`, async () => {
      const result = await run(client)

      expect(result.failure?.code).toBe('UNSUPPORTED_CONFIG_VERSION')
      expect(result.failure?.help).toBe(
        'Regenerate the config with a supported version.',
      )
      expect(result.failure?.url).toBe(
        'https://cipherstash.com/docs/errors/unsupported-config-version',
      )
      expect(result.failure?.message).toBe('encrypt config is invalid')
    })

    it(`${name} carries them through .withLockContext() too`, async () => {
      const result = await run(client).withLockContext(LOCK_CONTEXT)

      expect(result.failure?.code).toBe('UNSUPPORTED_CONFIG_VERSION')
      expect(result.failure?.help).toBe(
        'Regenerate the config with a supported version.',
      )
      expect(result.failure?.url).toBe(
        'https://cipherstash.com/docs/errors/unsupported-config-version',
      )
    })

    it(`${name} still pins code to the closed set, and authCode to the open one`, async () => {
      // Spreading a shared reader must not have relaxed either rule at any
      // mapper: `code` stays protect-ffi's closed set (so Node's own
      // `ECONNRESET` is dropped), `authCode` stays `@cipherstash/auth`'s open
      // one (so a code newer than this build still lands).
      mockState.rejection = () =>
        Object.assign(new Error('socket hang up'), {
          code: 'ECONNRESET',
          authCode: 'SOME_FUTURE_CODE',
        })

      const result = await run(client)

      expect(result.failure).not.toHaveProperty('code')
      expect(result.failure?.authCode).toBe('SOME_FUTURE_CODE')
    })
  }
})

describe('the two taxonomies keep their own rules', () => {
  it('pins `code` to the closed protect-ffi set', async () => {
    // Node sets `code` on its own errors. `ECONNRESET` is not an encryption
    // error code and must not be reported as one — the validation this shares
    // with `getErrorCode` is not allowed to weaken.
    mockState.rejection = () =>
      Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' })

    const result = await client.encrypt('a@b.com', {
      column: users.email,
      table: users,
    })

    expect(result.failure?.code).toBeUndefined()
    expect(result.failure?.message).toContain('socket hang up')
  })

  it('leaves `authCode` open — a code newer than this build still lands', async () => {
    // The auth taxonomy belongs to `@cipherstash/auth` and ships on its own
    // release train, so it is passed through unvalidated.
    mockState.rejection = () =>
      Object.assign(new Error('refused'), { authCode: 'SOME_FUTURE_CODE' })

    const result = await client.encrypt('a@b.com', {
      column: users.email,
      table: users,
    })

    expect(result.failure?.authCode).toBe('SOME_FUTURE_CODE')
  })

  it('sets no key the error did not carry', async () => {
    // An absent key and a key set to `undefined` read the same to
    // `if (failure.code)` but not to `'code' in failure`, and never to a
    // caller serialising the failure. Omit rather than write `undefined`.
    mockState.rejection = () => new Error('plain failure')

    const result = await client.encrypt('a@b.com', {
      column: users.email,
      table: users,
    })

    expect(result.failure?.message).toContain('plain failure')
    for (const key of ['code', 'authCode', 'help', 'url']) {
      expect(result.failure).not.toHaveProperty(key)
    }
  })

  it('ignores a non-string help or url', async () => {
    mockState.rejection = () =>
      Object.assign(new Error('boom'), { help: 42, url: { href: 'nope' } })

    const result = await client.encrypt('a@b.com', {
      column: users.email,
      table: users,
    })

    expect(result.failure).not.toHaveProperty('help')
    expect(result.failure).not.toHaveProperty('url')
    expect(result.failure?.message).toBe('boom')
  })
})
