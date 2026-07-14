/**
 * Structurally-valid EQL v3 storage envelopes, built without a CipherStash client.
 *
 * The `public.*` domain CHECKs are purely STRUCTURAL — e.g. `public.eql_v3_text_search`
 * requires an object with `v`/`i`/`c`/`hm`/`op`/`bf` and `v = '3'`. Nothing in
 * the CHECK is cryptographic. That lets the live
 * PostgREST suite drive the real adapter against real domains and real
 * `eql_v3` operators with no ZeroKMS round-trip, so it runs wherever
 * `DATABASE_URL` runs.
 *
 * What this CAN prove: the wire encoding PostgREST accepts, that a full storage
 * envelope clears the domain CHECK on every filter operand while a narrowed
 * `encryptQuery` term does not, that `cs` resolves to bloom containment, and
 * that the Supabase roles hold the grants those operators need.
 *
 * What it CANNOT prove: that ciphertext decrypts, or that ORE ordering is
 * semantically correct. `drizzle-v3/operators-live-pg.test.ts` covers those with
 * real credentials.
 */

/** `hm` — the HMAC equality term. Any stable string; equality is by identity. */
function hmacFor(value: string): string {
  return `hm-${value}`
}

/**
 * `ob` — one ORE block-256 term.
 *
 * `eql_v3_internal.compare_ore_block_256_term` derives the block count from the
 * ciphertext length and rejects anything else: the layout is
 * `[N PRP bytes][N*16B left][16B hash key][N*32B right]`, so
 * `octet_length = 49*N + 16`. N=1 → 65 bytes. A shorter term raises
 * "Malformed ORE term: <n> bytes" from inside the operator, which is a far more
 * confusing failure than a CHECK violation.
 *
 * Comparisons between two such terms EXECUTE but carry no order semantics — a
 * term only reliably compares equal to itself. Suites must not assert `<`/`>`
 * outcomes on synthetic terms.
 */
const ORE_TERM_BYTES = 49 * 1 + 16

function oreTermFor(seed: number): string {
  const byte = (seed % 251).toString(16).padStart(2, '0')
  return byte.repeat(ORE_TERM_BYTES)
}

/**
 * `op` — the CLLW-OPE term (eql-3.0.0 `_ord` / `text_search` domains): a
 * hex-encoded bytea, compared byte-wise. Any even-length hex string clears the
 * structural CHECK; identical seeds compare equal, which is all the suites
 * rely on (no `<`/`>` semantics on synthetic terms).
 */
function opeTermFor(seed: number): string {
  const byte = (seed % 251).toString(16).padStart(2, '0')
  return byte.repeat(16)
}

/** `bf` — the bloom filter for match/`cs`. A set of token positions. */
function bloomFor(tokens: number[]): number[] {
  return [...new Set(tokens)].sort((a, b) => a - b)
}

export type EnvelopeParts = {
  table: string
  column: string
  /** Distinguishes ciphertexts; also seeds the ORE term. */
  seed: number
  /** Present on equality-capable domains (`hm`). */
  hmac?: string
  /** Present on block-ORE order domains — `_ord_ore` (`ob`). */
  ore?: boolean
  /** Present on CLLW-OPE order domains — `_ord`, `text_search` (`op`). */
  ope?: boolean
  /** Present on match-capable domains (`bf`). */
  bloom?: number[]
}

/** A full STORAGE envelope — what `encrypt()` returns and every filter operand
 * must be. Includes `c`, which a narrowed `encryptQuery` term omits. */
export function storageEnvelope(parts: EnvelopeParts): Record<string, unknown> {
  const envelope: Record<string, unknown> = {
    v: '3',
    i: { t: parts.table, c: parts.column },
    c: `ct-${parts.column}-${parts.seed}`,
  }
  if (parts.hmac !== undefined) envelope.hm = hmacFor(parts.hmac)
  if (parts.ore) envelope.ob = [oreTermFor(parts.seed)]
  if (parts.ope) envelope.op = opeTermFor(parts.seed)
  if (parts.bloom) envelope.bf = bloomFor(parts.bloom)
  return envelope
}

/**
 * The narrowed query term the v2 dialect emits (`encryptQuery`): index terms
 * but NO `c`. The v3 domain CHECK requires `c`, so Postgres rejects this with
 * 23514 for EVERY domain — the reason `query-builder-v3.ts` sends full
 * envelopes as filter operands. The live suite asserts exactly that.
 */
export function narrowedQueryTerm(
  parts: EnvelopeParts,
): Record<string, unknown> {
  const { c: _dropped, ...rest } = storageEnvelope(parts)
  return rest
}
