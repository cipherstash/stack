import { expect, it } from 'vitest'
import { EncryptionV3 } from '@/encryption/v3'
import { encryptedTable, types } from '@/eql/v3'

/**
 * The property that makes `order=col->op` correct, asserted on the term itself.
 *
 * The Supabase adapter orders an encrypted column by its `op` term where it sits
 * inside the envelope, because PostgREST cannot emit the canonical
 * `ORDER BY eql_v3.ord_term(col)` — it cannot call a function. `ord_term()`
 * returns `eql_v3_internal.ope_cllw`, a domain over `bytea`, ordered by the
 * native btree. The jsonb path orders the same term as a STRING.
 *
 * Those agree only because of how the term is encoded. Postgres compares jsonb
 * strings with `varstr_cmp` under the database's default collation — `->` does
 * NOT avoid collation any more than `->>` does (measured: with `en_US.UTF-8`,
 * both order `'a'` before `'B'`, while `COLLATE "C"` does the reverse). What
 * saves us is that the term is FIXED-WIDTH LOWERCASE HEX:
 *
 *   - fixed width, so lexicographic order is positional order — no prefix effects;
 *   - `[0-9a-f]` only, and every collation orders digits before letters and hex
 *     letters among themselves.
 *
 * Change the term's encoding — variable width, uppercase, base64 — and ordering
 * through PostgREST silently stops matching `ord_term()`. This test is the
 * tripwire. The Drizzle adapter emits `ord_term()` directly and is unaffected.
 */
const table = encryptedTable('ope_term_probe', {
  amount: types.IntegerOrd('amount'),
  when: types.TimestampOrd('when'),
  name: types.TextSearch('name'),
})

const HEX = /^[0-9a-f]+$/

async function opTerms(
  values: readonly unknown[],
  column: 'amount' | 'when' | 'name',
) {
  const client = await EncryptionV3({ schemas: [table] })
  const terms: string[] = []
  for (const value of values) {
    const result = await client.encrypt(value as never, {
      column: table[column],
      table,
    })
    if (result.failure) throw new Error(result.failure.message)
    terms.push((result.data as { op: string }).op)
  }
  return terms
}

it('integer_ord op terms are fixed-width lowercase hex', async () => {
  const terms = await opTerms([-2147483648, -1, 0, 1, 2147483647], 'amount')

  expect(terms.every((term) => HEX.test(term))).toBe(true)
  expect(new Set(terms.map((term) => term.length)).size).toBe(1)
}, 300_000)

it('timestamp_ord op terms are fixed-width lowercase hex', async () => {
  const stamps = await opTerms(
    [new Date('1970-01-01T00:00:00Z'), new Date('2026-07-10T12:34:56Z')],
    'when',
  )

  expect(stamps.every((term) => HEX.test(term))).toBe(true)
  expect(new Set(stamps.map((term) => term.length)).size).toBe(1)
}, 300_000)

/**
 * Text terms are VARIABLE width — 16 hex chars per character, plus a 2-char
 * header (`'ada'` -> 50, `'zebra'` -> 82). That is not a defect: the blocks are
 * positional, so comparing the terms as strings compares the plaintexts
 * character by character, and a shorter term that is a prefix of a longer one
 * sorts first — exactly the semantics of comparing the strings themselves.
 *
 * Numeric and date terms must stay FIXED width, because there positional
 * comparison is only equivalent to numeric comparison when every term has the
 * same number of blocks.
 */
it('text op terms are hex, per-character, and order like their plaintexts', async () => {
  // Includes the prefix case (`ada` < `adam`), which is the one variable width
  // could plausibly get wrong.
  const ascending = ['ada', 'adam', 'zebra']
  const terms = await opTerms(ascending, 'name')

  expect(terms.every((term) => HEX.test(term))).toBe(true)
  expect(terms.map((term) => term.length)).toEqual([50, 66, 82])
  expect([...terms].sort()).toEqual(terms)
}, 300_000)

it('lexicographic order over the op terms reproduces plaintext order', async () => {
  // The whole point, stated directly: sorting the terms as strings — which is
  // what PostgREST does — must agree with sorting the plaintexts.
  const ascending = [-2147483648, -1, 0, 1, 2147483647]
  const terms = await opTerms(ascending, 'amount')

  expect([...terms].sort()).toEqual(terms)
}, 300_000)
