import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { EQL_V3_BUNDLE_SQL, EQL_V3_INSTALL_VERSION } from '../../src/migration/eql-v3-bundle'

const FIXTURE = join(import.meta.dirname, '../../__tests__/fixtures/cipherstash-encrypt-v3.sql')

describe('eql v3 bundle', () => {
  it('round-trips the fixture byte-for-byte through the vendor escaping', () => {
    // pins the vendor-script escaping chain: the embedded string MUST equal the
    // source SQL exactly, or a corrupted bundle ships and only fails at e2e.
    expect(EQL_V3_BUNDLE_SQL).toBe(readFileSync(FIXTURE, 'utf8'))
  })

  it('embeds a self-contained eql_v3 installer (no non-comment eql_v2 refs)', () => {
    expect(EQL_V3_INSTALL_VERSION).toMatch(/^eql-v3-/)
    const nonComment = EQL_V3_BUNDLE_SQL.split('\n').filter((l) => !l.trim().startsWith('--'))
    expect(nonComment.some((l) => l.includes('eql_v2'))).toBe(false)
  })

  it('defines the four text-scalar domains and the index-term extractors', () => {
    const nonComment = EQL_V3_BUNDLE_SQL.split('\n')
      .filter((l) => !l.trim().startsWith('--'))
      .join('\n')
    for (const d of ['eql_v3.text', 'eql_v3.text_eq', 'eql_v3.text_match', 'eql_v3.text_ord'])
      expect(nonComment).toContain(d)
    for (const fn of ['eq_term', 'ord_term', 'match_term']) expect(nonComment).toContain(fn)
  })
})
