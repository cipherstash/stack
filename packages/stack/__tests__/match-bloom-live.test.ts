import 'dotenv/config'
import { encrypt, encryptQuery, newClient } from '@cipherstash/protect-ffi'
import { beforeAll, describe, expect, it } from 'vitest'
import { defaultMatchOpts } from '@/schema/match-defaults'

/**
 * Pins what protect-ffi's match index ACTUALLY emits, against real ffi.
 *
 * This suite exists because a claim about ffi's bloom filter — that
 * `include_original: true` appends a whole-value token, so a substring `contains`
 * can never match — was asserted in a code comment, propagated into the docs and
 * the changeset, and then "confirmed" by `supabase-v3-pgrest-live.test.ts`, whose
 * credential-free fake built the extra token itself. Nothing tied that fake to
 * ffi, so the fiction round-tripped. It cost a bug report (CIP-3483) and a
 * limitation callout in the published docs.
 *
 * The invariant can only be observed where the bloom is actually built, so these
 * tests call ffi directly rather than going through a stack builder. They need
 * CipherStash credentials but no database.
 */
const TABLE = 'match_bloom_probe'
const COLUMN = 'col'

/** A match column, tokenized exactly as the shared defaults specify. */
const encryptConfigWith = (includeOriginal: boolean) => ({
  v: 1,
  tables: {
    [TABLE]: {
      [COLUMN]: {
        cast_as: 'text' as const,
        indexes: {
          match: { ...defaultMatchOpts(), include_original: includeOriginal },
        },
      },
    },
  },
})

type Client = Awaited<ReturnType<typeof newClient>>

describe('protect-ffi match bloom', () => {
  let withOriginal: Client
  let withoutOriginal: Client

  beforeAll(async () => {
    withOriginal = await newClient({
      encryptConfig: encryptConfigWith(true),
      eqlVersion: 3,
    })
    withoutOriginal = await newClient({
      encryptConfig: encryptConfigWith(false),
      eqlVersion: 3,
    })
  })

  const bloomOf = async (client: Client, plaintext: string) => {
    const payload = await encrypt(client, {
      plaintext,
      table: TABLE,
      column: COLUMN,
    })
    return (payload as { bf?: number[] }).bf ?? []
  }

  // The bloom of a QUERY term, produced the way a `matches` query actually
  // produces its needle — `encryptQuery` with the `match` index type, not
  // `encrypt`. This is the operand `eql_v3.matches` receives, so a subset test
  // against a stored `bloomOf` value is the real query path, not a same-function
  // artefact comparing `encrypt` to itself.
  const queryBloomOf = async (client: Client, plaintext: string) => {
    const term = await encryptQuery(client, {
      plaintext,
      table: TABLE,
      column: COLUMN,
      indexType: 'match',
    })
    return (term as { bf?: number[] }).bf ?? []
  }

  /**
   * ffi emits the bloom's bits in a nondeterministic ORDER — two encrypts of the
   * same plaintext on the same client differ in sequence while carrying the same
   * bits. Only the bit SET is meaningful (`@>` is `smallint[]` containment), so
   * every comparison here sorts first.
   */
  const sorted = (bits: number[]) => [...bits].sort((a, b) => a - b)

  // The claim, killed at its source. `include_original` is accepted by the
  // config and ignored: the bloom is the tokenizer's trigrams, nothing more.
  // If a future ffi starts honouring the flag, THIS fails — and the v3 domains
  // already emit `false` (see `eql/v3/columns.ts`), so `contains` keeps working.
  it.each([
    'Ada Lovelace',
    'ada@example.com',
  ])('emits the same bloom for %j whether include_original is on or off', async (plaintext) => {
    const on = await bloomOf(withOriginal, plaintext)
    const off = await bloomOf(withoutOriginal, plaintext)

    expect(sorted(on)).toEqual(sorted(off))
    // A trigram-only bloom, not one carrying an extra whole-value token: 6
    // bits (k) per DISTINCT trigram, so never more than 6 × the trigram count.
    expect(on.length).toBeLessThanOrEqual(6 * (plaintext.length - 2))
    expect(on.length).toBeGreaterThan(0)
  })

  // The corollary, and the reason `matchNeedleError` must reject short needles
  // instead of trusting `include_original` to make them matchable: below
  // `token_length` there are no trigrams, so the bloom is EMPTY under either
  // setting — and `stored_bf @> '{}'` is true for every row.
  it.each([
    ['with include_original', true],
    ['without include_original', false],
  ] as const)('blooms a sub-trigram value to nothing, %s', async (_label, on) => {
    const bloom = await bloomOf(on ? withOriginal : withoutOriginal, 'ad')

    expect(bloom).toEqual([])
  })

  // protect-ffi 0.30 closes the core fail-open path: query encryption itself
  // rejects empty-token needles, so callers that bypass every ORM guard still
  // cannot produce the match-all bloom operand reported in #697.
  it.each([
    [1, 'a'],
    [2, 'ad'],
  ] as const)('rejects the %i-character query needle in the core FFI', async (_length, needle) => {
    await expect(queryBloomOf(withOriginal, needle)).rejects.toThrow(
      /short|token|3|ngram/i,
    )
  })

  // The query needle's bloom is a subset of the STORED value's bloom — which is
  // exactly what `eql_v3.matches` (`match_term(stored) @> query_term(needle)`)
  // tests. The haystack is a stored `encrypt` value; each needle is an
  // `encryptQuery` `match` term, the real operand the containment query binds —
  // so this exercises the query path, not `encrypt` compared to itself. This is
  // the substring case CIP-3483 reported as broken, proven at the bloom layer;
  // `drizzle-v3/operators-live-pg.test.ts` proves the same thing through SQL.
  it('blooms a substring query needle into a subset of the stored value bloom', async () => {
    const haystack = new Set(await bloomOf(withOriginal, 'ada@example.com'))

    for (const needle of ['ada', 'example', 'ada@example.com']) {
      const bits = await queryBloomOf(withOriginal, needle)
      expect(bits.length).toBeGreaterThan(0)
      expect(bits.filter((bit) => !haystack.has(bit))).toEqual([])
    }

    // A needle sharing no trigram must NOT be a subset, or the assertion above
    // would hold for anything.
    const absent = await queryBloomOf(withOriginal, 'zzz')
    expect(absent.some((bit) => !haystack.has(bit))).toBe(true)
  })
})
