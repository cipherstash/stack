/**
 * Pins {@link explainUnresolved}'s fail-closed contract now that the domain
 * classifier recognises `eql_v3_*` only.
 *
 * `listEncryptedColumns` can no longer emit `version: 2` — a legacy
 * `eql_v2_encrypted` column is not classified as an EQL column at all, so it
 * never reaches this function as a candidate. Every pure-v2 table therefore
 * arrives here as an EMPTY candidate list, both pre-cutover (`<col>` /
 * `<col>_encrypted`) and post-cutover (the ciphertext renamed onto the
 * plaintext column's own name), and the first guard falls through on it.
 *
 * These tests exist so removing the now-unreachable `version === 2` branch is
 * provably behaviour-preserving, and so a future v2 sweep cannot delete the
 * empty-list guard the v2 lifecycle actually depends on. That guard has to hold
 * even when the manifest recorded an `encryptedColumn` — `backfill` records one
 * for v2 columns too — which is the `candidates.length > 0` gate on the
 * fail-closed path (#787 review).
 */

import type { EncryptedColumnInfo } from '@cipherstash/migrate'
import type pg from 'pg'
import { beforeEach, describe, expect, it, vi } from 'vitest'

// Only the two I/O boundaries are replaced. `pickEncryptedColumn` stays real —
// it IS the resolution rule under test, and stubbing it (as `encrypt-v3.test.ts`
// stubs `resolveColumnLifecycle`) is why the hint-discard below had no coverage.
const readManifest = vi.hoisted(() =>
  vi.fn(async () => null as { tables: Record<string, unknown[]> } | null),
)
const listEncryptedColumns = vi.hoisted(() =>
  vi.fn(async () => [] as EncryptedColumnInfo[]),
)
vi.mock('@cipherstash/migrate', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cipherstash/migrate')>()),
  readManifest,
  listEncryptedColumns,
}))

const { explainUnresolved, resolveColumnLifecycle } = await import(
  '../resolve-eql.js'
)

/**
 * A `pg` double answering only the `pg_attribute` existence probe, from a set
 * of column names the table is pretended to have. That probe is the whole
 * point: it is what separates "the hint is stale" from "the hint names a real
 * column that simply is not EQL v3".
 */
const clientWithColumns = (...columns: string[]): pg.ClientBase =>
  ({
    // `columnExists` binds [table, schema, column] — it splits schema-qualified
    // names and quotes with `format('%I')` so the lookup is case-EXACT. This
    // double matches case-exactly for the same reason: a case-insensitive
    // fixture would keep passing if the probe regressed to a bare
    // `to_regclass($1)`, which case-folds (#787 review).
    query: async (_sql: string, params: unknown[]) => ({
      rows: [{ exists: columns.includes(String(params[2])) }],
    }),
  }) as unknown as pg.ClientBase

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

  it('still falls through when no EQL v3 columns exist BUT a hint was recorded', () => {
    // The pure-v2 table. `encrypt backfill` records `encryptedColumn` for v2
    // columns too, so a hint is present on every table backfilled with this
    // release — it must not flip the empty-candidate fall-through into a
    // refusal, because `cutover` / `drop` in this same build still implement
    // the v2 ladder this falls through to (#787 review).
    expect(explainUnresolved('users', 'ssn', [], 'ssn_encrypted')).toBeNull()
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

/**
 * #772 review, finding 7 — the mixed-table dead end.
 *
 * `classifyEqlDomain` recognises `eql_v3_*` only, so on a table holding a v2
 * pair (`ssn` / `ssn_encrypted`) plus one unrelated v3 column, the v2 ciphertext
 * column is not a candidate at all. `pickEncryptedColumn`'s sole-EQL-column rule
 * then claims the unrelated v3 column for `ssn`.
 *
 * `encrypt backfill` records the true pairing in the manifest, so the answer is
 * on disk — but the hint was thrown away whenever it failed to resolve, and the
 * re-pick without it reached the sole rule. Recording the pairing changed
 * nothing, and `drop`'s remedy told the user to record the guess instead.
 */
describe('resolveColumnLifecycle — a recorded hint that is not a v3 candidate', () => {
  const V3_OTHER: EncryptedColumnInfo = {
    column: 'email_enc',
    domain: 'eql_v3_text_search',
    version: 3,
  }

  beforeEach(() => {
    vi.clearAllMocks()
    readManifest.mockResolvedValue(null)
    listEncryptedColumns.mockResolvedValue([])
  })

  it('does not fall back to the sole-column guess when the manifest names a counterpart', async () => {
    // The v2 pair is invisible to the classifier; only email_enc is a candidate.
    listEncryptedColumns.mockResolvedValue([V3_OTHER])
    readManifest.mockResolvedValue({
      tables: { users: [{ column: 'ssn', encryptedColumn: 'ssn_encrypted' }] },
    })

    const { info, unresolvedHint } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'ssn_encrypted', 'email_enc'),
      'users',
      'ssn',
    )

    expect(info).toBeNull()
    expect(unresolvedHint).toBe('ssn_encrypted')
  })

  // The pure-v2 shape, and the regression the `candidates.length > 0` gate
  // exists to prevent (#787 review). `backfill` records `encryptedColumn`
  // unconditionally — v2 included — so EVERY pure-v2 table backfilled with this
  // release carries a hint naming a real, existing, non-v3 column. Without the
  // gate, `columnExists` returned true, `unresolvedHint` was set, and
  // `cutover` / `drop` refused a lifecycle this same build still performs.
  it('does not fail closed on a pure-v2 table, where no v3 column can be mis-claimed', async () => {
    // No v3 columns at all: just the `ssn` / `ssn_encrypted` v2 pair, which the
    // classifier does not see.
    listEncryptedColumns.mockResolvedValue([])
    readManifest.mockResolvedValue({
      tables: { users: [{ column: 'ssn', encryptedColumn: 'ssn_encrypted' }] },
    })

    const { info, candidates, unresolvedHint } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'ssn_encrypted'),
      'users',
      'ssn',
    )

    expect(info).toBeNull()
    expect(candidates).toEqual([])
    // The fall-through signal: no hint reported, so `explainUnresolved` returns
    // null and the caller reaches its own v2 preconditions.
    expect(unresolvedHint).toBeUndefined()
    expect(
      explainUnresolved('users', 'ssn', candidates, unresolvedHint),
    ).toBeNull()
  })

  // #787 review. `columnExists` used to be a local copy using a bare
  // `to_regclass($1)`, which PARSES and case-folds its argument — so on a
  // Prisma-style `"User"` table the probe reported "missing", the hint was
  // treated as stale, and the fail-closed above silently did not fire. It fell
  // through to the sole/convention rules and resolved a guess, which is exactly
  // what #772 finding 7 exists to prevent. Now delegated to
  // `@cipherstash/migrate`'s shared, case-exact probe.
  it('fires the fail-closed on a mixed-case table name too', async () => {
    listEncryptedColumns.mockResolvedValue([V3_OTHER])
    readManifest.mockResolvedValue({
      tables: { User: [{ column: 'ssn', encryptedColumn: 'ssn_encrypted' }] },
    })

    const { info, unresolvedHint } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'ssn_encrypted', 'email_enc'),
      'User',
      'ssn',
    )

    expect(info).toBeNull()
    expect(unresolvedHint).toBe('ssn_encrypted')
  })

  it('explains the recorded counterpart by name rather than listing candidates', async () => {
    const message = explainUnresolved(
      'users',
      'ssn',
      [V3_OTHER],
      'ssn_encrypted',
    )

    expect(message).toContain('ssn_encrypted')
    expect(message).toContain('not an EQL v3 column')
    // Naming the guess here is what sent users to `--encrypted-column email_enc`.
    expect(message).not.toContain('--encrypted-column email_enc')
  })

  // The fallback the comment actually describes — a hint naming a column that
  // is simply gone — must still resolve through convention.
  it('still falls back to convention when the hint is genuinely stale', async () => {
    listEncryptedColumns.mockResolvedValue([
      { column: 'ssn_encrypted', domain: 'eql_v3_text_eq', version: 3 },
    ])
    readManifest.mockResolvedValue({
      tables: { users: [{ column: 'ssn', encryptedColumn: 'ssn_old' }] },
    })

    // `ssn_old` is gone from the table entirely — the genuinely stale case.
    const { info } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'ssn_encrypted'),
      'users',
      'ssn',
    )

    expect(info?.column).toBe('ssn_encrypted')
    expect(info?.via).toBe('convention')
  })

  it('resolves through the hint when it does name a candidate', async () => {
    listEncryptedColumns.mockResolvedValue([
      { column: 'ssn_enc', domain: 'eql_v3_text_eq', version: 3 },
    ])
    readManifest.mockResolvedValue({
      tables: { users: [{ column: 'ssn', encryptedColumn: 'ssn_enc' }] },
    })

    const { info, unresolvedHint } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'ssn_enc'),
      'users',
      'ssn',
    )

    expect(info?.column).toBe('ssn_enc')
    expect(info?.via).toBe('hint')
    expect(unresolvedHint).toBeUndefined()
  })

  // No manifest entry at all is the ordinary case; the sole rule still applies
  // and `drop`'s own `via === 'sole'` gate is what refuses it.
  it('leaves the sole-column rule alone when nothing was recorded', async () => {
    listEncryptedColumns.mockResolvedValue([V3_OTHER])

    const { info, unresolvedHint } = await resolveColumnLifecycle(
      clientWithColumns('ssn', 'email_enc'),
      'users',
      'ssn',
    )

    expect(info?.via).toBe('sole')
    expect(unresolvedHint).toBeUndefined()
  })
})
