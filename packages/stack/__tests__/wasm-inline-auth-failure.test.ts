/**
 * The WASM entry's half of the CTS usage-limit story.
 *
 * `__tests__/auth-failure-propagation.test.ts` proves it for the native entry.
 * This is the same proof for `@cipherstash/stack/wasm-inline` — the entry a
 * Cloudflare Workers / Deno / Supabase Edge caller uses — because a billing
 * refusal is entry-agnostic: it happens at token issuance, before any ZeroKMS
 * request, so an edge caller meets it exactly as often as a Node one.
 *
 * Three things are asserted here that the native suite cannot cover:
 *
 * 1. **Non-`Error` rejections.** wasm-bindgen rejects with the raw `JsValue`
 *    the Rust side produced and this build exports no error class, so a
 *    failure can arrive as a plain string or object. `toError` coerces it, and
 *    must not lose `authCode` / `help` on the way — it already preserves
 *    `code`.
 * 2. **`Encryption()` at init.** It throws rather than returning a `Result`,
 *    and is where a usage-limit refusal surfaces first.
 * 3. **Per-item bulk-decrypt failures**, which carry their own `authCode` /
 *    `help` since the batch call itself still resolves.
 *
 * Credential-free: the FFI and the auth strategy are both mocked.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

/** What CTS's 402 body says, verbatim. */
const CTS_MESSAGE = 'Insufficient balance. Please upgrade your plan.'

/**
 * The `miette` help and url `stack-auth` 0.42.3 attaches to
 * `UsageLimitExceeded`, verbatim. They are one remedy in two halves: `help` is
 * folded into the message, `url` reaches the caller only as its own field.
 */
const CTS_HELP = 'Upgrade the plan from the CipherStash dashboard, then retry.'
const CTS_URL = 'https://dashboard.cipherstash.com/billing'

/** The part of the remedy that lands in the message. */
const REMEDY = 'Upgrade the plan'

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

/**
 * The shape `error_to_js` produces in `crates/protect-ffi/src/wasm.rs`: a real
 * JS `Error` with the diagnostic fields `Reflect.set` onto it.
 */
const usageLimitError = () =>
  Object.assign(new Error(CTS_MESSAGE), {
    authCode: 'USAGE_LIMIT_EXCEEDED',
    help: CTS_HELP,
    url: CTS_URL,
  })

/**
 * The same refusal as a bare object. wasm-bindgen hands back whatever the Rust
 * side threw, and the WASM build ships no error class to `instanceof` against,
 * so this is the shape `toError` exists to rescue.
 */
const usageLimitObject = () => ({
  error: CTS_MESSAGE,
  authCode: 'USAGE_LIMIT_EXCEEDED',
  help: CTS_HELP,
  url: CTS_URL,
})

const ct = () => ({ v: 3, i: { t: 'users', c: 'email' }, c: 'x' }) as never

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

beforeEach(() => {
  vi.clearAllMocks()
})

describe('a usage-limit refusal on a wasm-inline operation', () => {
  it('carries the code and the remedy when the FFI rejects with an Error', async () => {
    ffi.encrypt.mockRejectedValueOnce(usageLimitError())

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.type).toBe('EncryptionError')
    expect(result.failure?.message).toBe(CTS_MESSAGE)
    expect(result.failure?.help).toBe(CTS_HELP)
    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  // The bug: `withResult` runs `onException` (`toError`) BEFORE the failure
  // mapper, so the mapper only ever sees the synthesized `Error`. `toError`
  // copies `code` across and nothing else, so an object-shaped refusal reached
  // an edge caller with `authCode: undefined` and no dashboard in the message
  // — while the identical refusal on Node carried both.
  it('carries them when the FFI rejects with a bare object', async () => {
    ffi.encrypt.mockRejectedValueOnce(usageLimitObject())

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(result.failure?.message).toContain(CTS_MESSAGE)
    expect(result.failure?.message).toContain(REMEDY)
  })

  // `help` is the rest of the taxonomy's remedy text — the codes this package
  // writes no remedy of its own for still have one, and it is dropped unless
  // `toError` carries the field.
  it("carries stack-auth's own help across the same coercion", async () => {
    ffi.decrypt.mockRejectedValueOnce({
      error: 'Not authenticated',
      authCode: 'NOT_AUTHENTICATED',
      help: 'Log in with `stash login`, or set `CS_CLIENT_ACCESS_KEY`.',
    })

    const c = await client()
    const result = await c.decrypt(ct())

    expect(result.failure?.type).toBe('DecryptionError')
    expect(result.failure?.authCode).toBe('NOT_AUTHENTICATED')
    expect(result.failure?.message).toContain('stash login')
  })

  // The neighbouring shapes must not regress: a string rejection has nothing
  // to carry, and `code` must still survive the coercion it always did.
  it('leaves a string rejection alone — nothing to carry, message intact', async () => {
    ffi.encrypt.mockRejectedValueOnce('boom from rust')

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.message).toBe('boom from rust')
    expect(result.failure?.authCode).toBeUndefined()
  })

  it('still carries `code` off a bare object, and claims no authCode', async () => {
    ffi.encrypt.mockRejectedValueOnce({
      code: 'UNKNOWN_COLUMN',
      detail: 'bad domain',
    })

    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })

    expect(result.failure?.code).toBe('UNKNOWN_COLUMN')
    expect(result.failure?.authCode).toBeUndefined()
  })
})

describe('a usage-limit refusal at wasm-inline client init', () => {
  /** `Encryption()` throws rather than returning a `Result`. */
  async function initFailure(rejection: unknown) {
    ffi.newClient.mockRejectedValueOnce(rejection)
    try {
      await client()
    } catch (thrown) {
      return thrown as Error & { authCode?: string }
    }
    throw new Error('expected Encryption() to reject')
  }

  // The bug: `wasmNewClient` was called bare, with no `wasmResult` / `toFailure`
  // around it, so the rejection propagated verbatim — while the native entry
  // folded in the remedy and attached the code at the same point.
  it("keeps stack-auth's message and remedy separate", async () => {
    const error = await initFailure(usageLimitError())

    expect(error.message).toBe(`[encryption]: ${CTS_MESSAGE}`)
    expect(error.help).toBe(CTS_HELP)
    // The link is the other half of the remedy and is deliberately NOT in the
    // message — it reaches the caller as a field.
    expect(error.url).toBe(CTS_URL)
    expect(error.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('keeps the code branchable on the thrown error', async () => {
    const error = await initFailure(usageLimitError())

    expect(error.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('prefixes like every other throw from this factory', async () => {
    const error = await initFailure(usageLimitError())

    expect(error.message).toContain('[encryption]:')
  })

  it('does not let a foreign `code` reach the thrown init error', async () => {
    // `code` is the one carried key with a CLOSED type, and the init path
    // reached the caller through `carryDiagnostics` alone — which copies keys
    // structurally, on purpose, so it cannot drop a field protect-ffi adds
    // next. That left this seam accepting anything: a fetch failing inside a
    // JS auth strategy rejects with `ECONNRESET`, and the caller got it
    // wearing `ProtectErrorCode`. `toFailure` had always screened it, so the
    // two seams of this entry disagreed about the same check.
    const error = await initFailure(
      Object.assign(new Error('socket hang up'), {
        code: 'ECONNRESET',
        authCode: 'SOME_FUTURE_REFUSAL',
      }),
    )

    expect(error).not.toHaveProperty('code')
    // The open set is untouched: a code newer than this build still arrives.
    expect(error.authCode).toBe('SOME_FUTURE_REFUSAL')
  })

  it('keeps a real protect-ffi code on the thrown init error', async () => {
    const error = await initFailure(
      Object.assign(new Error('bad config'), {
        code: 'UNSUPPORTED_CONFIG_VERSION',
      }),
    )

    expect(error.code).toBe('UNSUPPORTED_CONFIG_VERSION')
  })

  it('rescues a bare-object refusal at init too', async () => {
    const error = await initFailure(usageLimitObject())

    expect(error.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(error.message).toContain(REMEDY)
  })

  it('leaves a non-auth init failure its own message', async () => {
    const error = await initFailure(new Error('encrypt config is invalid'))

    expect(error.message).toContain('encrypt config is invalid')
    expect(error.message).not.toContain(REMEDY)
    expect(error.authCode).toBeUndefined()
  })

  // `help` and `url` are one remedy split across two fields, and `url` is the
  // one a boundary quietly drops after growing support for the first. It is
  // not prospective: `@cipherstash/auth` declares `help?` / `url?` on
  // `FailureBase`, so a JS strategy can supply a url today and protect-ffi
  // relays it verbatim. `carryDiagnostics` copies fields rather than naming
  // them, so this holds for whatever it gains next — asserted, not assumed.
  it('carries the whole miette remedy, url included', async () => {
    const error = (await initFailure(
      Object.assign(new Error(CTS_MESSAGE), {
        authCode: 'USAGE_LIMIT_EXCEEDED',
        help: CTS_HELP,
        url: CTS_URL,
      }),
    )) as Error & { help?: string; url?: string }

    expect(error.help).toBe(CTS_HELP)
    expect(error.url).toBe(CTS_URL)
  })

  it('sets no diagnostic field the failure did not carry', async () => {
    const error = await initFailure(new Error('plain failure'))

    for (const key of ['code', 'authCode', 'help', 'url']) {
      expect(error).not.toHaveProperty(key)
    }
  })
})

/**
 * The diagnostic an OPERATION failure carries, as distinct from a thrown init
 * error. `toFailure` named `code` and `authCode` and stopped there, so `help`
 * reached an edge caller only folded into prose and `url` reached them by no
 * path at all — while the init error two describes up carried both. Routing
 * through the shared `failureDiagnostics` is what closed that.
 */
describe('the diagnostic on a wasm-inline operation failure', () => {
  async function failureFrom(rejection: unknown) {
    ffi.encrypt.mockRejectedValueOnce(rejection)
    const c = await client()
    const result = await c.encrypt('a@b.com', {
      table: users,
      column: users.email,
    })
    return result.failure
  }

  it('carries help and url alongside the codes', async () => {
    const failure = await failureFrom(
      Object.assign(new Error(CTS_MESSAGE), {
        code: 'UNKNOWN_COLUMN',
        authCode: 'USAGE_LIMIT_EXCEEDED',
        help: CTS_HELP,
        url: CTS_URL,
      }),
    )

    expect(failure).toMatchObject({
      code: 'UNKNOWN_COLUMN',
      authCode: 'USAGE_LIMIT_EXCEEDED',
      help: CTS_HELP,
      url: CTS_URL,
    })
  })

  it('omits an empty help or url rather than carrying the empty string', async () => {
    const failure = await failureFrom(
      Object.assign(new Error('boom'), { help: '', url: '' }),
    )

    expect(failure).not.toHaveProperty('help')
    expect(failure).not.toHaveProperty('url')
  })

  it('sets no diagnostic key the failure did not carry', async () => {
    const failure = await failureFrom(new Error('plain failure'))

    for (const key of ['code', 'authCode', 'help', 'url']) {
      expect(failure).not.toHaveProperty(key)
    }
  })

  // The billing codes are the shape that actually occurs: as of stack-auth
  // 0.42.3 `UsageLimitExceeded` sets both `help(..)` and `url(..)`, so a
  // usage-limit refusal carries both halves of the remedy. `url` is the half
  // that reaches a caller ONLY as a field — it is never folded into the
  // message — so a boundary dropping it loses the link entirely.
  it('carries help and url for a usage-limit refusal', async () => {
    const failure = await failureFrom(usageLimitError())

    expect(failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(failure?.help).toBe(CTS_HELP)
    expect(failure?.url).toBe(CTS_URL)
  })

  // Most of the taxonomy still sets only `help(..)`, and an absent url must
  // stay an absent KEY rather than one holding `undefined`.
  it('leaves url absent for a code that carries none', async () => {
    const failure = await failureFrom(
      Object.assign(new Error('Not authenticated'), {
        authCode: 'NOT_AUTHENTICATED',
        help: 'Run `stash auth login`.',
      }),
    )

    expect(failure?.help).toBe('Run `stash auth login`.')
    expect(failure).not.toHaveProperty('url')
  })
})

/**
 * A billing refusal during a bulk decrypt fails the WHOLE call, never one row.
 *
 * That is structural, not incidental. `DecryptResult::from_error` is the only
 * constructor of the failure arm, and it fills `authCode` only for
 * `Error::Auth` / `Error::ZeroKMS(Auth)` — neither of which can reach it. The
 * three things that do are a ciphertext parse failure, a `Plaintext` /
 * `JsPlaintext` conversion, and a `RecordDecryptError`, each a variant of its
 * own. The token is resolved once for the call, and its refusal leaves through
 * `?` on `decrypt_fallible` (`crates/protect-ffi/src/lib.rs`, and the identical
 * wasm twin in `src/wasm.rs`), so the batch fails outright.
 *
 * So these assert the refusal on the path it actually takes — a rejection —
 * and that the per-row path claims nothing auth-shaped.
 */
describe('a usage-limit refusal during a wasm-inline bulk decrypt', () => {
  it('fails the whole call with the code and the remedy', async () => {
    ffi.decryptBulkFallible.mockRejectedValueOnce(usageLimitError())

    const c = await client()
    const result = await c.bulkDecrypt([ct(), ct()])

    expect(result.failure?.type).toBe('DecryptionError')
    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(result.failure?.help).toBe(CTS_HELP)
  })

  it('does the same for the model decrypt engine', async () => {
    ffi.decryptBulkFallible.mockRejectedValueOnce(usageLimitError())

    const c = await client()
    const result = await c.bulkDecryptModels([{ email: ct() }], users)

    expect(result.failure?.type).toBe('DecryptionError')
    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(result.failure?.message).toBe(CTS_MESSAGE)
    expect(result.failure?.help).toBe(CTS_HELP)
  })

  it('claims no authCode for per-row failures, and names every one', async () => {
    // Per-row failures are parse / type / record-decrypt only. The aggregate
    // reports each index and its `code`, and does NOT invent an auth code from
    // rows that cannot carry one.
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { error: 'bad ciphertext', code: 'INVALID_CIPHERTEXT' },
      { error: 'not a plaintext', code: 'UNKNOWN' },
    ] as never)

    const c = await client()
    const result = await c.bulkDecrypt([ct(), ct()])

    expect(result.failure?.type).toBe('DecryptionError')
    expect(result.failure?.authCode).toBeUndefined()
    expect(result.failure?.message).toContain('[0] (INVALID_CIPHERTEXT)')
    expect(result.failure?.message).toContain('[1] (UNKNOWN)')
    expect(result.failure?.message).toContain('bad ciphertext')
    expect(result.failure?.message).toContain('not a plaintext')
  })

  it('names the failing field for the model engine', async () => {
    ffi.decryptBulkFallible.mockResolvedValueOnce([
      { error: 'bad ciphertext', code: 'INVALID_CIPHERTEXT' },
    ] as never)

    const c = await client()
    const result = await c.bulkDecryptModels([{ email: ct() }], users)

    expect(result.failure?.authCode).toBeUndefined()
    expect(result.failure?.message).toContain('email')
    expect(result.failure?.message).toContain('INVALID_CIPHERTEXT')
  })
})
