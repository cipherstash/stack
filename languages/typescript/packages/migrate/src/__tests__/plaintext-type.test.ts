import { describe, expect, it } from 'vitest'
import { formatCodes, plaintextSerializer } from '../decrypt.js'
import { plaintextTypeForEqlDomain } from '../plaintext-type.js'

describe('plaintextTypeForEqlDomain', () => {
  it.each([
    ['eql_v3_text', 'text'],
    ['eql_v3_text_eq', 'text'],
    ['eql_v3_text_match', 'text'],
    ['eql_v3_text_ord', 'text'],
    ['eql_v3_text_ord_ore', 'text'],
    ['eql_v3_text_ord_ope', 'text'],
    ['eql_v3_text_search', 'text'],
    ['eql_v3_text_search_ore', 'text'],
    ['eql_v3_integer_ord', 'integer'],
    ['eql_v3_smallint_eq', 'smallint'],
    ['eql_v3_bigint_ord_ore', 'bigint'],
    ['eql_v3_numeric', 'numeric'],
    ['eql_v3_real_ord', 'real'],
    ['eql_v3_double_eq', 'double precision'],
    ['eql_v3_boolean', 'boolean'],
    ['eql_v3_date_ord', 'date'],
    // An instant, not a wall-clock time — see the module docs.
    ['eql_v3_timestamp_ord', 'timestamptz'],
    ['eql_v3_json', 'jsonb'],
    ['eql_v3_json_search', 'jsonb'],
  ])('%s → %s', (domain, sqlType) => {
    expect(plaintextTypeForEqlDomain(domain)?.sqlType).toBe(sqlType)
  })

  it('accepts the public-qualified form the SDK records', () => {
    expect(plaintextTypeForEqlDomain('public.eql_v3_text_search')).toEqual({
      domain: 'eql_v3_text_search',
      family: 'text',
      sqlType: 'text',
    })
  })

  it.each([
    // SteVec fragments and query needles are never a column's type.
    'eql_v3_json_entry',
    'eql_v3_json_query',
    // Legacy v2 has no per-domain plaintext type to recover.
    'eql_v2_encrypted',
    // A suffix this release does not know: refuse rather than guess.
    'eql_v3_text_fuzzy',
    'eql_v3_boolean_eq',
    // A family this release does not know.
    'eql_v3_uuid',
    'eql_v30_text',
    'text',
  ])('refuses %s', (domain) => {
    expect(plaintextTypeForEqlDomain(domain)).toBeNull()
  })
})

describe('plaintextSerializer', () => {
  it('serialises scalars for a scalar column, casting left to Postgres', () => {
    const serialize = plaintextSerializer('integer')
    expect(serialize(42)).toBe('42')
    expect(serialize(9007199254740993n)).toBe('9007199254740993')
    expect(serialize(true)).toBe('true')
    expect(serialize('x')).toBe('x')
    expect(serialize(new Date('2024-02-29T10:11:12Z'))).toBe(
      '2024-02-29T10:11:12.000Z',
    )
  })

  it('treats a NULL decrypt of a scalar as unwritable (skipped), never as NULL', () => {
    expect(plaintextSerializer('text')(null)).toBeUndefined()
    expect(plaintextSerializer('text')(undefined)).toBeUndefined()
  })

  it('keeps JSON meaning for json/jsonb targets, including scalar documents', () => {
    const serialize = plaintextSerializer('jsonb')
    expect(serialize({ a: 1 })).toBe('{"a":1}')
    expect(serialize('doc')).toBe('"doc"')
    expect(serialize(null)).toBe('null')
    expect(plaintextSerializer(' JSON ')(7)).toBe('7')
  })
})

describe('formatCodes', () => {
  it('orders by count then code, and says so when there are none', () => {
    expect(formatCodes({ UNKNOWN: 1, INVALID_CIPHERTEXT: 3 })).toBe(
      '3 × INVALID_CIPHERTEXT, 1 × UNKNOWN',
    )
    expect(formatCodes({})).toBe('no error codes reported')
  })
})
