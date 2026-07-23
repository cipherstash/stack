/**
 * Pins {@link explainUnresolved}'s fail-closed contract now that the domain
 * classifier recognises `eql_v3_*` only.
 *
 * `listEncryptedColumns` can no longer emit `version: 2` — a legacy
 * `eql_v2_encrypted` column is not classified as an EQL column at all, so it
 * never reaches this function as a candidate. The post-cutover v2 state (the
 * ciphertext renamed onto the plaintext column's own name) therefore arrives
 * here as an EMPTY candidate list, which the first guard already falls through
 * on. These tests exist so removing the now-unreachable `version === 2` branch
 * is provably behaviour-preserving, and so a future v2 sweep cannot delete the
 * empty-list guard the v2 lifecycle actually depends on.
 */

import type { EncryptedColumnInfo } from '@cipherstash/migrate'
import { describe, expect, it } from 'vitest'
import { explainUnresolved } from '../resolve-eql.js'

const v3 = (
  column: string,
  domain = 'eql_v3_text_eq',
): EncryptedColumnInfo => ({
  column,
  domain,
  version: 3,
})

describe('explainUnresolved', () => {
  it('falls through (null) when the table has no EQL columns at all', () => {
    // Both the not-yet-backfilled case and the post-cutover v2 same-name case
    // land here: the caller's own preconditions produce the accurate error.
    expect(explainUnresolved('users', 'email', [])).toBeNull()
  })

  it('fails closed, naming every candidate, when none is identifiable', () => {
    const message = explainUnresolved('users', 'email', [
      v3('a_enc'),
      v3('b_enc', 'eql_v3_text_search'),
    ])

    expect(message).toContain('Cannot identify which encrypted column')
    expect(message).toContain('a_enc (eql_v3_text_eq)')
    expect(message).toContain('b_enc (eql_v3_text_search)')
    expect(message).toContain('--encrypted-column')
  })

  it('gives no free pass to a candidate sharing the plaintext column name', () => {
    // The removed branch exempted a SAME-NAME candidate, but only at
    // `version === 2`. A v3 domain on the plaintext column's own name is not
    // the post-cutover state (v3 has no cut-over rename), so it must still
    // fail closed rather than let a destructive command guess a lifecycle.
    const message = explainUnresolved('users', 'email', [
      v3('email'),
      v3('email_enc'),
    ])

    expect(message).toContain('Cannot identify which encrypted column')
  })
})
