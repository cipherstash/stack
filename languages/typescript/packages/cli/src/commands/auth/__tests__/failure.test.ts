import { describe, expect, it } from 'vitest'
import {
  authFailureCliCode,
  authFailureHint,
  authFailureMessage,
} from '../failure.js'

const LOGIN_HINT = 'Run `stash auth login` and try again.'

/**
 * An `AuthFailure` as `@cipherstash/auth` returns it.
 *
 * `type` is optional because the module's own `RenderableFailure` widens it to
 * `string | undefined` — so `undefined` and `''` are both shapes the lookups
 * have to survive, not hypotheticals the type system rules out.
 */
const failure = (type: string | undefined, message: string, help?: string) => ({
  ...(type === undefined ? {} : { type }),
  error: new Error(message),
  ...(help ? { help } : {}),
})

describe('authFailureMessage', () => {
  it("appends stack-auth's help to the diagnosis", () => {
    // `miette` help is not part of an error's `Display`, so the remedy was
    // dropped at every call site: "Not authenticated" with no mention of how
    // to authenticate.
    expect(
      authFailureMessage(
        failure(
          'NOT_AUTHENTICATED',
          'Not authenticated',
          'Log in with `stash auth login`.',
        ),
      ),
    ).toBe('Not authenticated. Log in with `stash auth login`.')
  })

  it('leaves a failure without help exactly as it was', () => {
    expect(authFailureMessage(failure('INVALID_CLIENT', 'bad client'))).toBe(
      'bad client',
    )
  })

  it('does not double a terminal full stop', () => {
    expect(
      authFailureMessage(failure('SERVER_ERROR', 'Boom.', 'Try later.')),
    ).toBe('Boom. Try later.')
  })

  // A CTS diagnosis is a sentence written by whoever raised it, and `.` is not
  // the only way one ends. `'Insufficient balance. Please upgrade your plan.'`
  // is the code path everyone tested; `'Upgrade now!'` is the one that came
  // back as `'Upgrade now!. See the dashboard.'`
  it.each([
    ['a full stop', 'Boom.', 'Boom. Try later.'],
    ['an exclamation mark', 'Upgrade now!', 'Upgrade now! Try later.'],
    [
      'a question mark',
      'Insufficient balance?',
      'Insufficient balance? Try later.',
    ],
    ['no punctuation at all', 'Boom', 'Boom. Try later.'],
  ])('joins help to a diagnosis ending in %s', (_what, message, expected) => {
    expect(
      authFailureMessage(failure('SERVER_ERROR', message, 'Try later.')),
    ).toBe(expected)
  })

  it('is the help alone when the diagnosis is empty', () => {
    // Otherwise the separator is all that survives: '. Try later.'
    expect(authFailureMessage(failure('SERVER_ERROR', '', 'Try later.'))).toBe(
      'Try later.',
    )
  })
})

describe('authFailureHint', () => {
  it('sends a usage-limit refusal to the dashboard instead of to login', () => {
    // The whole reason this function exists. `LOGIN_HINT` is the right advice
    // for a stale session and wrong for a billing refusal — a fresh login
    // cannot mint a credential CTS is withholding on billing grounds.
    const hint = authFailureHint(
      failure(
        'USAGE_LIMIT_EXCEEDED',
        'Insufficient balance.',
        'Upgrade at https://dashboard.cipherstash.com/billing.',
      ),
      LOGIN_HINT,
    )

    expect(hint).toContain('https://dashboard.cipherstash.com')
    expect(hint).not.toContain('auth login')
  })

  it('sends an unprovisioned org to support, not to billing', () => {
    // A 402 has two causes and they need different remedies: an org over its
    // allowance upgrades, an org the usage system has never heard of has
    // nothing to buy.
    const hint = authFailureHint(
      failure(
        'ORG_NOT_PROVISIONED',
        'Not provisioned.',
        'Contact https://cipherstash.com/support.',
      ),
      LOGIN_HINT,
    )

    expect(hint).toContain('https://cipherstash.com/support')
    expect(hint).not.toContain('dashboard.cipherstash.com')
  })

  it('keeps the caller-supplied hint for an ordinary auth failure', () => {
    expect(
      authFailureHint(failure('EXPIRED_TOKEN', 'Token expired'), LOGIN_HINT),
    ).toBe(LOGIN_HINT)
  })

  it('has no hint of its own when the caller supplies none', () => {
    expect(
      authFailureHint(failure('EXPIRED_TOKEN', 'Token expired')),
    ).toBeUndefined()
  })

  // `type` is `string | undefined` by design (see `RenderableFailure`), so all
  // three of these reach the lookup. An empty type is the one that bit: the
  // old `(failure.type && MAP.get(failure.type)) ?? fallback` short-circuited
  // to `''`, which is not nullish, so `??` never reached the fallback and
  // `stash env` built a `MintError` with `hint: ''` — suppressed by its own
  // `if (failure.hint)` guard, i.e. no hint at all.
  it.each([
    ['an empty type', ''],
    ['an absent type', undefined],
    ['a type this CLI has never heard of', 'SOME_FUTURE_CODE'],
  ])('falls back to the caller hint for %s', (_what, type) => {
    expect(authFailureHint(failure(type, 'boom'), LOGIN_HINT)).toBe(LOGIN_HINT)
  })
})

describe('authFailureCliCode', () => {
  // The JSON stream's `code` is the only machine-readable field on it. An
  // agent that reads `session_invalid` runs `stash auth login` and comes
  // straight back here — which is the loop for BOTH terminal codes, not just
  // the billing one.
  it.each([
    ['USAGE_LIMIT_EXCEEDED', 'usage_limit_exceeded'],
    ['ORG_NOT_PROVISIONED', 'org_not_provisioned'],
  ])('reports %s as its own terminal code', (type, expected) => {
    expect(
      authFailureCliCode(failure(type, 'refused'), 'session_invalid'),
    ).toBe(expected)
  })

  it.each([
    ['an ordinary auth failure', 'EXPIRED_TOKEN'],
    ['an empty type', ''],
    ['an absent type', undefined],
    ['a type this CLI has never heard of', 'SOME_FUTURE_CODE'],
  ])('keeps the caller-supplied code for %s', (_what, type) => {
    expect(authFailureCliCode(failure(type, 'boom'), 'session_invalid')).toBe(
      'session_invalid',
    )
  })

  it('has a CLI code for every code that gets a terminal hint', () => {
    // The two tables are what drifted: `ORG_NOT_PROVISIONED` had a hint saying
    // "logging in again will not clear this" while its code still said
    // `session_invalid`. Adding a terminal code has to land in both.
    for (const type of ['USAGE_LIMIT_EXCEEDED', 'ORG_NOT_PROVISIONED']) {
      expect(
        authFailureHint(
          failure(type, 'refused', 'Upstream remedy.'),
          LOGIN_HINT,
        ),
      ).toBe('Upstream remedy.')
      expect(
        authFailureCliCode(failure(type, 'refused'), 'session_invalid'),
      ).not.toBe('session_invalid')
    }
  })
})

describe('the pinned auth taxonomy', () => {
  it('maps a usage refusal to terminal guidance and a stable CLI code', () => {
    const refusal = failure(
      'USAGE_LIMIT_EXCEEDED',
      'Insufficient balance.',
      'Upgrade the plan.',
    )
    expect(authFailureHint(refusal, LOGIN_HINT)).not.toBe(LOGIN_HINT)
    expect(authFailureCliCode(refusal, 'session_invalid')).toBe(
      'usage_limit_exceeded',
    )
  })
})
