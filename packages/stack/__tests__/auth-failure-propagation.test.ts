/**
 * End-to-end proof that a CTS usage-limit refusal reaches a caller as
 * something they can act on, on the two paths they actually meet it.
 *
 * The failure originates at token issuance: every ZeroKMS operation resolves a
 * service token first, so CTS answering `402 USAGE_LIMIT_EXCEEDED` means no
 * ZeroKMS request is made at all. protect-ffi surfaces that as a thrown `Error`
 * with `authCode` and stack-auth's `help` (see `Error::auth_error` in
 * `packages/protect-ffi/crates/protect-ffi/src/lib.rs`); this asserts the SDK
 * folds the dashboard remedy into `message` and keeps the code for branching.
 *
 * Credential-free: protect-ffi is mocked, so there is no CTS round-trip.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'

/** What CTS's 402 body says, verbatim — the whole message a caller had before. */
const CTS_MESSAGE = 'Insufficient balance. Please upgrade your plan.'

/** The shape protect-ffi throws for a stack-auth failure. */
const usageLimitRefusal = () =>
  Object.assign(new Error(CTS_MESSAGE), {
    authCode: 'USAGE_LIMIT_EXCEEDED',
    // `help` and `url` verbatim from `stack-auth` 0.42.3's
    // `#[diagnostic(help(..), url(..))]` on `UsageLimitExceeded`. They are the
    // authoritative remedy, and the two halves land in different places: `help`
    // is folded into the message, `url` reaches the caller as its own field.
    help: 'The organisation has used its allowance for the current billing period. Upgrade the plan from the CipherStash dashboard, then retry.',
    url: 'https://dashboard.cipherstash.com/billing',
  })

vi.mock('@cipherstash/protect-ffi', async (importOriginal) => ({
  // `isProtectErrorCode` is real: `getErrorCode` runs it over the thrown
  // error's `code`, and stubbing it would let a wrong answer here pass.
  ...(await importOriginal<typeof import('@cipherstash/protect-ffi')>()),
  newClient: vi.fn(async () => ({ __mock: 'client' })),
  encrypt: vi.fn(async () => {
    throw usageLimitRefusal()
  }),
}))

import * as ffi from '@cipherstash/protect-ffi'
import { encryptedTable, types } from '@/encryption/v3'
import { Encryption } from '@/index'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
})

beforeEach(() => {
  vi.clearAllMocks()
})

/** `Encryption()` throws rather than returning a `Result`, so catch to inspect. */
async function initFailure() {
  vi.mocked(ffi.newClient).mockRejectedValueOnce(usageLimitRefusal())
  try {
    await Encryption({ schemas: [users] })
  } catch (thrown) {
    return thrown as Error & { authCode?: string }
  }
  throw new Error('expected Encryption() to reject')
}

describe('a usage-limit refusal at client init', () => {
  it("keeps stack-auth's message and remedy separate", async () => {
    const error = await initFailure()

    expect(error.message).toBe(`[encryption]: ${CTS_MESSAGE}`)
    expect(error.help).toContain('Upgrade the plan')
  })

  it('hands over the billing link as its own field', async () => {
    // `url` is the other half of the same remedy and is never folded into the
    // message, so it reaches a caller only here. Before this it reached them
    // by no path at all.
    const error = await initFailure()

    expect(error.url).toBe('https://dashboard.cipherstash.com/billing')
  })

  it('keeps the code branchable on the thrown error', async () => {
    const error = await initFailure()

    expect(error.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })
})

describe('any failure at client init', () => {
  /**
   * The full diagnostic protect-ffi throws: the `Display` message, its own
   * `ProtectErrorCode`, and `miette`'s `help` / `url`, which are not part of
   * `Display` and so reach JS only as fields.
   *
   * `url` is inert until protect-ffi lands it, and is asserted here anyway:
   * a mapper that enumerates the fields it knows drops the next one silently,
   * which is how `help` was lost in the first place.
   */
  const fullDiagnostic = () =>
    Object.assign(new Error('encrypt config is invalid'), {
      code: 'UNSUPPORTED_CONFIG_VERSION',
      help: 'Regenerate the config with a supported version.',
      url: 'https://cipherstash.com/docs/errors/unsupported-config-version',
    })

  /**
   * `Encryption()` throws rather than returning a `Result`, and a thrown
   * failure must be classifiable the same way a returned one is. Before this,
   * only `authCode` rode across: `code` was dropped by the mapper (which had no
   * field for it) and `help` / `url` never left protect-ffi's error at all, so
   * an init failure could not be triaged the way an operation failure could.
   */
  async function throwsFrom(rejection: unknown) {
    vi.mocked(ffi.newClient).mockRejectedValueOnce(rejection)
    try {
      await Encryption({ schemas: [users] })
    } catch (thrown) {
      return thrown as Error & {
        code?: string
        authCode?: string
        help?: string
        url?: string
      }
    }
    throw new Error('expected Encryption() to reject')
  }

  it('carries the protect-ffi error code onto the thrown error', async () => {
    expect((await throwsFrom(fullDiagnostic())).code).toBe(
      'UNSUPPORTED_CONFIG_VERSION',
    )
  })

  it('carries `help` onto the thrown error', async () => {
    const error = await throwsFrom(fullDiagnostic())

    // The structured field survives initialization independently of the
    // upstream diagnostic message.
    expect(error.help).toBe('Regenerate the config with a supported version.')
  })

  it('carries a `url` it has no built-in knowledge of', async () => {
    expect((await throwsFrom(fullDiagnostic())).url).toBe(
      'https://cipherstash.com/docs/errors/unsupported-config-version',
    )
  })

  it('sets nothing it was not given', async () => {
    const error = await throwsFrom(new Error('plain failure'))

    expect(error.message).toContain('plain failure')
    for (const key of ['code', 'authCode', 'help', 'url']) {
      expect(error).not.toHaveProperty(key)
    }
  })

  // "Absent, never empty" is now stated in three places — protect-ffi
  // normalises empty to absent at the boundary, `failureDiagnostics` drops
  // empty strings, and both entries are asserted on it. An empty `help` is not
  // a remedy and an empty `url` is not a link, and the difference is invisible
  // to `if (err.help)` but not to `'help' in err` or to anything serialising
  // the error onward. This entry carried `help: ''` for a day; nothing failed.
  it('omits an empty help or url rather than carrying the empty string', async () => {
    const error = await throwsFrom(
      Object.assign(new Error('boom'), { help: '', url: '' }),
    )

    expect(error).not.toHaveProperty('help')
    expect(error).not.toHaveProperty('url')
  })

  // `url` is a real channel — protect-ffi relays whatever miette or a JS
  // strategy supplied. As of stack-auth 0.42.3 the two terminal refusals set
  // `url(..)` as well as `help(..)`, so a usage-limit refusal now arrives with
  // both; the rest of the taxonomy still sets only `help(..)`, and an absent
  // url must stay an absent KEY rather than one holding `undefined`.
  it('passes a url through, and leaves it absent when there is none', async () => {
    const withUrl = await throwsFrom(
      Object.assign(new Error('boom'), {
        url: 'https://cipherstash.com/docs/errors/some-code',
      }),
    )
    expect(withUrl.url).toBe('https://cipherstash.com/docs/errors/some-code')

    // The shape a usage-limit refusal actually has: help AND url.
    const usageLimit = await throwsFrom(usageLimitRefusal())
    expect(usageLimit.help).toBeDefined()
    expect(usageLimit.url).toBe('https://dashboard.cipherstash.com/billing')

    // A code that carries help and no url — most of the taxonomy.
    const helpOnly = await throwsFrom(
      Object.assign(new Error('Not authenticated'), {
        authCode: 'NOT_AUTHENTICATED',
        help: 'Run `stash auth login`.',
      }),
    )
    expect(helpOnly.help).toBeDefined()
    expect(helpOnly).not.toHaveProperty('url')
  })

  it('carries the whole diagnostic for a usage-limit refusal too', async () => {
    const error = await throwsFrom(usageLimitRefusal())

    expect(error.authCode).toBe('USAGE_LIMIT_EXCEEDED')
    expect(error.help).toBe(
      'The organisation has used its allowance for the current billing period. Upgrade the plan from the CipherStash dashboard, then retry.',
    )
  })
})

describe('a usage-limit refusal on an operation', () => {
  it('is an EncryptionError carrying the same remedy and code', async () => {
    const client = await Encryption({ schemas: [users] })

    const result = await client.encrypt('person@example.com', {
      column: users.email,
      table: users,
    })

    expect(result.failure?.type).toBe('EncryptionError')
    expect(result.failure?.message).toBe(CTS_MESSAGE)
    expect(result.failure?.help).toContain('Upgrade the plan')
    expect(result.failure?.url).toBe(
      'https://dashboard.cipherstash.com/billing',
    )
    expect(result.failure?.authCode).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('leaves `code` to protect-ffi, which claims none for an auth failure', () => {
    // The two taxonomies stay separate: `code` is protect-ffi's closed
    // `ProtectErrorCode` set, `authCode` is stack-auth's open one.
    expect(usageLimitRefusal()).not.toHaveProperty('code')
  })
})
