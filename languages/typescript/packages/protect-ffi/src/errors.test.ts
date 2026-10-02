import { describe, expect, it } from 'vitest'
import {
  getAuthErrorCode,
  isProtectErrorCode,
  PROTECT_ERROR_CODES,
} from './errors.js'

describe('isProtectErrorCode', () => {
  it('accepts every declared code', () => {
    for (const code of PROTECT_ERROR_CODES) {
      expect(isProtectErrorCode(code)).toBe(true)
    }
  })

  it('rejects a Node error code', () => {
    // Why this checks the value and not just the field's presence: `err.code`
    // is not ours alone. A caller reading the field structurally without
    // validating it would see a socket failure as one of these.
    expect(isProtectErrorCode('ECONNRESET')).toBe(false)
    expect(isProtectErrorCode('ERR_INVALID_ARG_TYPE')).toBe(false)
  })

  it('rejects non-strings', () => {
    expect(isProtectErrorCode(undefined)).toBe(false)
    expect(isProtectErrorCode(null)).toBe(false)
    expect(isProtectErrorCode(42)).toBe(false)
    expect(isProtectErrorCode({ toString: () => 'UNKNOWN_COLUMN' })).toBe(false)
  })
})

describe('narrowing a thrown error', () => {
  /** What both bindings throw: an ordinary Error with `code` set by Rust. */
  const thrown = (message: string, code?: string) =>
    code === undefined
      ? new Error(message)
      : Object.assign(new Error(message), { code })

  it('reads the code a caller would branch on', () => {
    const err: unknown = thrown('Invalid JSON path', 'INVALID_JSON_PATH')

    const { code } = err as { code?: unknown }
    expect(isProtectErrorCode(code) && code === 'INVALID_JSON_PATH').toBe(true)
  })

  it('finds no code on a failure that has none', () => {
    // The `#[error(transparent)]` variants wrap a cipherstash-client failure
    // whose text this repo does not own, so no code is attached. Before #146
    // this case was decided by whether a substring table happened to match the
    // upstream wording.
    const err: unknown = thrown('some cipherstash-client failure')

    expect(isProtectErrorCode((err as { code?: unknown }).code)).toBe(false)
  })

  it('does not accept a foreign code', () => {
    const err: unknown = thrown('connection reset', 'ECONNRESET')

    expect(isProtectErrorCode((err as { code?: unknown }).code)).toBe(false)
  })
})

describe('no message-shape routing', () => {
  // One message per pattern the deleted `inferErrorCode` table matched on.
  // Each used to be enough on its own to produce a code; none is now, because
  // nothing reads the message any more. This is the regression that would mean
  // the string matching had crept back — most plausibly as a "fallback for
  // errors that arrive without a code", which is the same guess in a smaller
  // box.
  const OLD_TABLE_MESSAGES = [
    'protect-ffi invariant violation: something impossible',
    "Unknown query operation: 'frobnicate'",
    "Invalid query input for 'match': received number, expected string.",
    "Invalid match query on column 'email': tokenizes to nothing.",
    "Invalid JSON path 'name': not a path.",
    'column users.email not found in Encrypt config',
    "Column 'email' does not have a 'match' index configured.",
    'ste_vec index on users.meta requires plaintext_type: json (found text)',
    'match index on users.age requires plaintext_type: text (found int)',
    'unsupported config version: 2 (expected 1)',
    'Invalid eqlVersion 4: expected 2 or 3',
    "Column 'users.email' cannot be represented in EQL v3: no v3 domain.",
    'EQL v3 conversion failed: bad payload',
    'Invalid EQL ciphertext: could not parse mp_base85',
  ]

  it.each(OLD_TABLE_MESSAGES)('yields no code for %j', (message) => {
    const err: unknown = new Error(message)

    expect(isProtectErrorCode((err as { code?: unknown }).code)).toBe(false)
  })
})

describe('getAuthErrorCode', () => {
  /**
   * What both bindings throw for a stack-auth failure: the ordinary Error,
   * plus `authCode` and the remedy text stack-auth wrote — see
   * `Error::auth_error` in `crates/protect-ffi/src/lib.rs`.
   */
  const authThrown = (message: string, authCode: string) =>
    Object.assign(new Error(message), { authCode })

  it('reads the code off an auth failure', () => {
    const err: unknown = authThrown(
      'Insufficient balance. Please upgrade your plan.',
      'USAGE_LIMIT_EXCEEDED',
    )

    expect(getAuthErrorCode(err)).toBe('USAGE_LIMIT_EXCEEDED')
  })

  it('is undefined for a failure that did not come from auth', () => {
    // The distinction the field exists to make: absent means "not an auth
    // failure", which is why it is unset rather than null.
    const err: unknown = Object.assign(new Error('column not found'), {
      code: 'UNKNOWN_COLUMN',
    })

    expect(getAuthErrorCode(err)).toBeUndefined()
  })

  it('does not confuse `code` for `authCode`', () => {
    // The two taxonomies are separate on purpose — see `ProtectAuthErrorCode`.
    const err: unknown = Object.assign(new Error('boom'), { code: 'UNKNOWN' })

    expect(getAuthErrorCode(err)).toBeUndefined()
  })

  it('survives non-objects and non-string codes', () => {
    expect(getAuthErrorCode(undefined)).toBeUndefined()
    expect(getAuthErrorCode(null)).toBeUndefined()
    expect(getAuthErrorCode('USAGE_LIMIT_EXCEEDED')).toBeUndefined()
    expect(getAuthErrorCode({ authCode: 42 })).toBeUndefined()
  })

  it('accepts a code this build has never heard of', () => {
    // The set is stack-auth's and moves on its own release train, so a newer
    // code than the pinned crate must still reach the caller rather than
    // being filtered to undefined.
    expect(getAuthErrorCode({ authCode: 'SOME_FUTURE_CODE' })).toBe(
      'SOME_FUTURE_CODE',
    )
  })
})
