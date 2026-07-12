import { expect, it } from 'vitest'
import { EncryptionV3 } from '@/encryption/v3'
import { encryptedTable, types } from '@/eql/v3'

/**
 * The invariant `contains()` rests on, asserted directly on the wire rather than
 * inferred from a query result.
 *
 * `eql_v3.contains(a, b)` is `match_term(a) @> match_term(b)`: bloom-filter
 * (`smallint[]`) containment. So a substring search can only work if
 *
 *     bloom(needle) ⊆ bloom(haystack)
 *
 * The match index tokenizes into downcased 3-grams. With `include_original: true`
 * the WHOLE value is bloomed as an extra token. That is right for STORAGE and
 * wrong for a QUERY operand: a whole-needle token is, by definition, not a
 * trigram of the haystack, so the subset relation breaks and every strict
 * substring search returns zero rows — silently.
 *
 * Both v3 adapters build match operands with `encrypt` (the full storage
 * envelope), not `encryptQuery`, because PostgREST cannot cast a filter value to
 * `eql_v3.query_*`. They are therefore structurally exposed. Today it is masked:
 * protect-ffi ignores `include_original` altogether, so neither side carries the
 * whole-value token and two bugs cancel out. See cipherstash/stack#615.
 *
 * WHEN protect-ffi STARTS HONOURING `include_original`, this file goes red — and
 * that is the intent. The subset assertion below is the precondition; the query
 * tests in the text family are the symptom. Fixing it means the operand must
 * stop carrying the original token (via `encryptQuery`, or by disabling the flag
 * on the query path) — not relaxing this test.
 */
const docs = encryptedTable('match_bloom_probe', {
  bio: types.TextMatch('bio'),
})

const HAYSTACK = 'ada@example.com'

async function bloomOf(
  client: Awaited<ReturnType<typeof EncryptionV3>>,
  value: string,
) {
  const result = await client.encrypt(value, { column: docs.bio, table: docs })
  if (result.failure) throw new Error(result.failure.message)
  const envelope = result.data as { bf?: number[] }
  if (!Array.isArray(envelope.bf)) {
    throw new Error(
      `Expected a bloom filter (bf) on the envelope for "${value}"`,
    )
  }
  return new Set(envelope.bf)
}

const isSubset = (needle: Set<number>, haystack: Set<number>) =>
  [...needle].every((bit) => haystack.has(bit))

it.each([
  // Degenerate: the whole needle IS a trigram, so it holds under either
  // behaviour. Passing this proves nothing about `include_original`.
  { label: '3-character needle (one trigram)', needle: 'ada' },
  // The discriminating cases: strict substrings longer than one trigram. These
  // are what break the moment a whole-needle token enters the operand.
  { label: 'interior substring, 7 chars', needle: 'a@examp' },
  { label: 'trailing substring, 4 chars', needle: '.com' },
  { label: 'the whole value', needle: HAYSTACK },
])('bloom(needle) is a subset of bloom(haystack) for a $label', async ({
  needle,
}) => {
  const client = await EncryptionV3({ schemas: [docs] })
  const haystack = await bloomOf(client, HAYSTACK)
  const probe = await bloomOf(client, needle)

  expect(HAYSTACK.includes(needle)).toBe(true)
  expect(
    isSubset(probe, haystack),
    `bloom("${needle}") is not contained in bloom("${HAYSTACK}"). ` +
      'The operand carries a token the haystack lacks — most likely the ' +
      '`include_original` whole-value token. See the file header.',
  ).toBe(true)
}, 120_000)

it('a needle absent from the haystack is NOT a bloom subset', async () => {
  // Without this, an implementation that blooms every needle to the empty set
  // would satisfy every assertion above.
  const client = await EncryptionV3({ schemas: [docs] })
  const haystack = await bloomOf(client, HAYSTACK)
  const probe = await bloomOf(client, 'qqqzzz')

  expect(isSubset(probe, haystack)).toBe(false)
}, 120_000)

it('a needle blooms to a non-empty filter', async () => {
  const client = await EncryptionV3({ schemas: [docs] })
  expect((await bloomOf(client, 'ada')).size).toBeGreaterThan(0)
}, 120_000)

/**
 * The subset assertions above are only worth having if they can FAIL. A whole-
 * value `include_original` token is, from the bloom's point of view, just a
 * token the haystack does not have — so simulate one by unioning in the bits of
 * a value the haystack never saw, and confirm the subset relation collapses.
 *
 * This is a test of the test. It is the reason the substring cases can be
 * trusted to catch `include_original` leaking into the query operand, rather
 * than passing for some unrelated reason.
 */
it('the subset assertion detects a single foreign token in the operand', async () => {
  const client = await EncryptionV3({ schemas: [docs] })
  const haystack = await bloomOf(client, HAYSTACK)
  const substring = await bloomOf(client, 'a@examp')
  const foreign = await bloomOf(client, 'qqqzzz')

  // The honest operand is contained...
  expect(isSubset(substring, haystack)).toBe(true)
  // ...and one extra token is enough to break it.
  const polluted = new Set([...substring, ...foreign])
  expect(isSubset(polluted, haystack)).toBe(false)
}, 120_000)
