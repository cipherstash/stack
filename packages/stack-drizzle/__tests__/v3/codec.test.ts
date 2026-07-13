import { describe, expect, it } from 'vitest'
import { EqlV3CodecError, v3FromDriver, v3ToDriver } from '../../src/v3/codec'

// A realistic `public.eql_v3_text_eq` envelope: schema version, table/column
// identifier, mp_base85 ciphertext, HMAC term. The trivial `{v:1,c:'ct'}`
// fixture this replaced could not distinguish an envelope from a bare object.
const ENVELOPE = {
  v: 3,
  i: { t: 'users', c: 'email' },
  c: 'mBbKmbNmNhX@Vv0N%<Ke7fH(=Zc*d4rDy0h3~yPZLq!kGm8x7$2Fw<TnR>1jQvA',
  hm: '3a1f9c0e5b7d2a48e6c1f0b93d7a2e58c4b6f19d0e3a7c25b8f14d69a0c3e7b2',
} as const

// SteVec documents carry the root ciphertext at `sv[0].c` and have no top-level
// `c` — the envelope guard must accept them.
const STE_VEC_ENVELOPE = {
  v: 3,
  k: 'sv',
  i: { t: 'users', c: 'profile' },
  sv: [{ c: 'mBbKciphertext', s: 'selector', b: 'term' }],
} as const

describe('v3 codec', () => {
  it('serialises an envelope to a jsonb string', () => {
    expect(v3ToDriver(ENVELOPE as never)).toBe(JSON.stringify(ENVELOPE))
  })

  it('maps null/undefined to SQL NULL (JS null), never the JSON null literal', () => {
    expect(v3ToDriver(null)).toBeNull()
    expect(v3ToDriver(undefined)).toBeNull()
  })

  it('round-trips a realistic envelope through both directions', () => {
    const serialised = v3ToDriver(ENVELOPE as never)
    expect(v3FromDriver(serialised)).toEqual(ENVELOPE)
  })

  it('round-trips unicode and a long ciphertext', () => {
    const envelope = {
      ...ENVELOPE,
      i: { t: 'users', c: 'café_☕' },
      c: 'z'.repeat(8192),
    }
    expect(v3FromDriver(v3ToDriver(envelope as never))).toEqual(envelope)
  })

  it('passes an already-parsed envelope through unchanged', () => {
    expect(v3FromDriver(ENVELOPE as never)).toBe(ENVELOPE)
  })

  it('accepts a SteVec document, whose ciphertext lives at sv[0].c', () => {
    expect(v3FromDriver(STE_VEC_ENVELOPE as never)).toBe(STE_VEC_ENVELOPE)
    expect(v3FromDriver(JSON.stringify(STE_VEC_ENVELOPE))).toEqual(
      STE_VEC_ENVELOPE,
    )
  })

  // `sv: []` has no `sv[0]`, so the guard's premise — a ciphertext at the
  // decryption root — does not hold. Presence of the key is not enough.
  it.each([
    ['an empty SteVec', { v: 3, k: 'sv', sv: [] }],
    ['a non-array SteVec', { v: 3, k: 'sv', sv: {} }],
    ['a null SteVec with no c', { v: 3, k: 'sv', sv: null }],
  ])('rejects %s', (_label, envelope) => {
    expect(() => v3FromDriver(envelope as never)).toThrow(EqlV3CodecError)
    expect(() => v3FromDriver(envelope as never)).toThrow(/ciphertext/)
  })

  it('still accepts a scalar envelope, which has c and no sv', () => {
    expect(v3FromDriver(ENVELOPE as never)).toBe(ENVELOPE)
  })

  it('normalises null/undefined to SQL NULL (JS null) on read', () => {
    expect(v3FromDriver(null)).toBeNull()
    expect(v3FromDriver(undefined)).toBeNull()
  })

  it('does not throw on a stray bigint in the envelope (defensive)', () => {
    expect(v3ToDriver({ ...ENVELOPE, v: 3n } as never)).toContain('"v":"3"')
  })

  // Before these, a malformed string surfaced a raw SyntaxError and a
  // wrong-shape payload was returned as-is — `v3FromDriver('5')` yielded `5`
  // typed as an envelope, which then reached `decrypt` as garbage.
  describe('malformed and non-envelope payloads', () => {
    it.each([
      '{bad',
      '',
      '{"v":3,',
    ])('throws EqlV3CodecError on unparseable jsonb %j', (raw) => {
      expect(() => v3FromDriver(raw)).toThrow(EqlV3CodecError)
      expect(() => v3FromDriver(raw)).toThrow(/Failed to parse/)
    })

    // The parse failure is the only codec path with an upstream error to
    // preserve. Flattening it to a message string discards the SyntaxError and
    // its stack, so a caller debugging a corrupt column loses where parsing
    // actually broke.
    it.each([
      '{bad',
      '',
      '{"v":3,',
    ])('preserves the underlying SyntaxError as `cause` for %j', (raw) => {
      let thrown: unknown
      try {
        v3FromDriver(raw)
      } catch (error) {
        thrown = error
      }

      expect(thrown).toBeInstanceOf(EqlV3CodecError)
      expect((thrown as EqlV3CodecError).cause).toBeInstanceOf(SyntaxError)
    })

    it.each([
      '5',
      '"a string"',
      'true',
      '[]',
      '[{"v":3,"c":"ct"}]',
    ])('throws on valid JSON %j that is not an envelope', (raw) => {
      expect(() => v3FromDriver(raw)).toThrow(EqlV3CodecError)
    })

    it('throws on an object missing the schema version', () => {
      expect(() => v3FromDriver({ c: 'ct' })).toThrow(/missing "v"/)
    })

    it('throws on an object carrying no ciphertext', () => {
      expect(() => v3FromDriver({ v: 3, i: { t: 'u', c: 'e' } })).toThrow(
        /missing a ciphertext/,
      )
    })

    it('throws on an array', () => {
      expect(() => v3FromDriver([ENVELOPE] as never)).toThrow(/got an array/)
    })
  })
})
