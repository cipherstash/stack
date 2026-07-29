/**
 * The legacy-EQL-v2 fixture matrix: which catalog domains a v2 READ suite mints
 * fixtures for, and — explicitly, with a written reason — which it does not.
 *
 * Schema authoring is EQL v3-only, so nothing in the product can write a v2
 * payload any more. But customers hold v2 rows written before they upgraded, and
 * those must stay readable forever. The only way to test that is to mint v2
 * fixtures straight through protect-ffi (`newClient({ eqlVersion: 2 })`), which
 * makes every such suite integration-only.
 *
 * This module is the SELECTION and PLANNING half of those suites, shared so that
 * the native, `wasm-inline` and DynamoDB surfaces cannot quietly disagree about
 * which domains they claim to cover. It deliberately builds nothing entry-
 * specific: it hands back column builders, a batched fixture plan, and a
 * row-assembly function, and each suite supplies its own `encryptedTable` /
 * `Encryption` / FFI entry point.
 *
 * COVERAGE DEFAULTS TO ON. {@link V2_MINT_DEFERRED} is a `Partial<Record<
 * EqlV3TypeName, string>>`, so a domain added to the catalog is exercised until
 * someone writes down why it should not be — the same discipline as
 * `DomainSpec.deferred`, and for the same reason: a silently-missing domain is
 * the failure mode that made this file necessary. The annotation also rejects a
 * key that is no longer a domain, so the exclusions cannot outlive their subject.
 *
 * One honest limit worth stating: these fixtures are v2 WIRE written by the
 * CURRENT client, not bytes written by the client a customer actually ran in
 * 2024. That is the strongest fixture the shipped binding can produce; it pins
 * the envelope and the plaintext encoding, not the whole history of them.
 */
import type { AnyEncryptedV3Column, JsonValue } from '@cipherstash/stack/eql/v3'
import type { CastAs } from '@cipherstash/stack/schema'
import {
  type DomainSpec,
  type EqlV3TypeName,
  eqlTypeSlug,
  typedEntries,
  V3_MATRIX,
} from './catalog.ts'

/**
 * Why `public.eql_v3_json_search` has no v2 fixture: the shipped client refuses
 * to write one. This is a hard refusal in cipherstash-client 0.42, not a gap in
 * this harness — the strings are in the binding itself:
 *
 *   "eqlVersion 2 cannot emit ste_vec ciphertexts with cipherstash-client 0.42;
 *    use eqlVersion 3"
 *   "SteVec documents use the v3 envelope wire format and cannot be emitted as a
 *    v2 storage payload; use encrypt_eql_v3"
 *
 * Reading a legacy v2 SteVec document is still supported (`decrypt` accepts both
 * wire generations, and the v2 SteVec shapes remain in protect-ffi's input
 * union) — it simply cannot be proven from a freshly-minted fixture, because no
 * fresh v2 SteVec fixture can exist. This is the one deferral that costs a whole
 * plaintext axis, which is why it is also listed in
 * {@link V2_UNREACHABLE_CAST_AS}.
 */
const STE_VEC_NOT_MINTABLE =
  'cipherstash-client 0.42 refuses to emit a ste_vec ciphertext in EQL v2 mode ' +
  '("eqlVersion 2 cannot emit ste_vec ciphertexts with cipherstash-client 0.42; ' +
  'use eqlVersion 3"), so no v2 JSON fixture can be minted at all. Legacy v2 ' +
  'SteVec documents on disk remain decryptable; that read is simply not ' +
  'reachable from a fixture this harness can produce.'

/**
 * Why the CLLW-OPE (`_ord`) domains have no v2 fixture — and this one is a
 * judgement about the DATA, not a workaround for a flaky test.
 *
 * A v2 payload from an `ope`-indexed column is not legacy data; it is data that
 * never existed. Two independent facts say so:
 *
 *  - The EQL v2 scalar payload has no slot for an OPE term. Its shape is
 *    `{ k, v, i, c, hm?, bf?, ob? }` — HMAC, bloom filter, block-ORE. `op` is an
 *    EQL v3 addition (protect-ffi's `EncryptedScalar`).
 *  - The v2 authoring path this branch removed never emitted `ope` anyway. Its
 *    `orderAndRange()` set `indexes.ore`; `ope` appeared only in the config
 *    VALIDATOR, never in a built column.
 *
 * So minting one would exercise a configuration no customer can be holding, and
 * whose behaviour under a v2-mode `encrypt` is undefined by construction (the
 * binding's own diagnostic for a term with nowhere to go is "Unknown Index Term
 * for column '…' in table '…'").
 *
 * It costs no read coverage. Decrypt reconstruction is driven by `cast_as`, not
 * by indexes, and every deferred domain here shares its `cast_as` with a covered
 * sibling — `date_ord` with `date` / `date_eq` / `date_ord_ore`, `text_search`
 * with `text` / `text_eq`, and so on. {@link v2UndeclaredCastAs} is the
 * executable form of that claim, so it cannot rot into a false comment.
 *
 * The block-ORE (`_ord_ore`) domains are NOT deferred, and the contrast matters:
 * `ore` is precisely what the v2 authoring path emitted for an ordered column,
 * so those payloads are the real legacy shape. (They carry a separate
 * `DomainSpec.deferred` in the catalog, but that is about a Postgres operator
 * class being superuser-only — a storage concern, irrelevant to decrypt, and
 * deliberately not consulted here.)
 */
const OPE_IS_NOT_A_V2_SHAPE =
  'CLLW-OPE has no representation in the EQL v2 wire (a v2 scalar payload ' +
  'carries hm/bf/ob only, never op), and the removed v2 authoring path emitted ' +
  '`ore` for ordered columns, never `ope`. A v2 payload from an ope-indexed ' +
  'column is therefore not legacy data but data that never existed. No read ' +
  'coverage is lost: this domain shares its cast_as — the axis decrypt actually ' +
  'reconstructs from — with a covered sibling.'

/**
 * Domains the v2 fixture matrix does not mint, and why.
 *
 * ANNOTATED, not `satisfies`: the annotation is what makes an unknown or stale
 * key a compile error, and what makes a NEWLY ADDED domain default to covered.
 * Deleting a row here re-enables the domain; that is the intended way to change
 * the coverage, and it shows up as a reviewable diff either way.
 */
export const V2_MINT_DEFERRED: Partial<Record<EqlV3TypeName, string>> = {
  'public.eql_v3_json_search': STE_VEC_NOT_MINTABLE,

  // Every `ope`-indexed domain. Kept as an explicit list rather than derived
  // from `indexes.ope` so that a future ope-indexed domain lands in the covered
  // set and fails loudly, instead of inheriting an exclusion nobody reviewed.
  // `v2OpeIndexedDomains()` cross-checks the two, so the list cannot drift from
  // the rule it claims to encode.
  'public.eql_v3_integer_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_smallint_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_bigint_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_date_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_timestamp_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_numeric_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_real_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_double_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_text_ord': OPE_IS_NOT_A_V2_SHAPE,
  'public.eql_v3_text_search': OPE_IS_NOT_A_V2_SHAPE,
}

/**
 * Plaintext axes (`cast_as`) that NO mintable domain reaches, and why.
 *
 * Deferring a domain is usually free — a sibling covers the same `cast_as`, and
 * `cast_as` is the only thing decrypt reconstruction reads. Deferring the LAST
 * domain on an axis is not free, and this map is where that has to be admitted
 * out loud. {@link v2UndeclaredCastAs} turns "admitted" into a test.
 */
export const V2_UNREACHABLE_CAST_AS: Partial<Record<CastAs, string>> = {
  json: STE_VEC_NOT_MINTABLE,
}

/** One domain the matrix mints fixtures for. */
export type V2FixtureDomain = Readonly<{
  /** Physical column name in the fixture table, e.g. `eql_v3_date_eq`. */
  slug: string
  eqlType: EqlV3TypeName
  spec: DomainSpec
}>

/** One domain the matrix does not mint, with the reason it does not. */
export type V2DeferredDomain = Readonly<{
  slug: string
  eqlType: EqlV3TypeName
  reason: string
}>

/**
 * One (domain, sample) fixture: what to encrypt, and what decrypting it must
 * give back.
 *
 * `plaintext` and `sample` differ only for the date-like domains, and the split
 * is what makes this harness entry-agnostic. A `Date` handed to the NATIVE
 * binding survives because neon's extractor runs `JSON.stringify` on it; the
 * WASM binding has no such step and its own entry converts explicitly. Handing
 * the FFI the ISO string both paths would end up with removes the difference.
 * `sample` stays the `Date`, because that is what the v3 table's `cast_as`
 * obliges `decryptModel` to reconstruct.
 */
export type V2FixtureCase = Readonly<{
  /** `public.eql_v3_date_eq #1` — a vitest `it.each` label. */
  label: string
  slug: string
  eqlType: EqlV3TypeName
  /** The plaintext axis decrypt reconstructs from. The thing actually under test. */
  castAs: CastAs
  /** Expected value after decrypt + reconstruction. */
  sample: DomainSpec['samples'][number]
  /** Value to hand the FFI. Date-like samples arrive here as ISO strings. */
  plaintext: string | number | bigint | boolean | JsonValue
  /** Which batched model row this fixture belongs to. */
  row: number
}>

/**
 * The whole batched plan. `cases` is also the ENCRYPT ORDER: protect-ffi's
 * `encryptBulk` correlates results positionally, so a suite can zip its output
 * straight against this array (and {@link v2ModelRows} does).
 */
export type V2FixturePlan = Readonly<{
  domains: readonly V2FixtureDomain[]
  cases: readonly V2FixtureCase[]
  /** Number of batched model rows: the widest domain's sample count. */
  rowCount: number
  deferred: readonly V2DeferredDomain[]
}>

function catalogRows(): Array<[EqlV3TypeName, DomainSpec]> {
  // Explicit type arguments for the same reason as `matrix-crypto`: `V3_MATRIX`
  // is `as const`, so without them `spec` infers as the union of 40 distinct row
  // literals and optional fields fail to resolve on rows that omit them.
  return typedEntries<EqlV3TypeName, DomainSpec>(V3_MATRIX)
}

/**
 * Domains whose configured indexes include `ope`. Exported so a suite can assert
 * that {@link V2_MINT_DEFERRED} still says exactly what
 * {@link OPE_IS_NOT_A_V2_SHAPE} claims it says — the list is hand-written on
 * purpose (so a new domain defaults to covered), and this is what stops it
 * drifting away from its own rationale.
 */
export function v2OpeIndexedDomains(): EqlV3TypeName[] {
  return catalogRows()
    .filter(([, spec]) => spec.indexes?.ope !== undefined)
    .map(([eqlType]) => eqlType)
}

/** Build the batched fixture plan from the catalog. */
export function v2FixturePlan(): V2FixturePlan {
  const domains: V2FixtureDomain[] = []
  const deferred: V2DeferredDomain[] = []

  for (const [eqlType, spec] of catalogRows()) {
    const slug = eqlTypeSlug(eqlType)
    const reason = V2_MINT_DEFERRED[eqlType]
    if (reason === undefined) {
      domains.push({ slug, eqlType, spec })
    } else {
      deferred.push({ slug, eqlType, reason })
    }
  }

  const cases: V2FixtureCase[] = []
  let rowCount = 0
  for (const domain of domains) {
    rowCount = Math.max(rowCount, domain.spec.samples.length)
    domain.spec.samples.forEach((sample, row) => {
      cases.push({
        label: `${domain.eqlType} #${row}`,
        slug: domain.slug,
        eqlType: domain.eqlType,
        castAs: domain.spec.castAs,
        sample,
        plaintext: sample instanceof Date ? sample.toISOString() : sample,
        row,
      })
    })
  }

  return { domains, cases, rowCount, deferred }
}

/**
 * One column builder per mintable domain, keyed by slug — the shape
 * `encryptedTable()` takes. Column names are the catalog slugs, which are unique
 * and never collide with `EncryptedTable`'s reserved property names.
 */
export function v2FixtureColumns(
  plan: V2FixturePlan,
): Record<string, AnyEncryptedV3Column> {
  const columns: Record<string, AnyEncryptedV3Column> = {}
  for (const domain of plan.domains) {
    columns[domain.slug] = domain.spec.builder(domain.slug)
  }
  return columns
}

/**
 * Reassemble a positional `encryptBulk` result into model rows: row `i` carries
 * every domain's `samples[i]`, and domains with fewer samples are simply absent
 * from the later rows (the model paths skip absent fields).
 *
 * Batching this way is what keeps a ~40-domain matrix to two network calls
 * instead of ~100. THROWS on a length mismatch rather than silently producing
 * short rows: a mis-zipped batch would assert the wrong domain's value against
 * the wrong sample and could pass by coincidence.
 */
export function v2ModelRows<T>(
  plan: V2FixturePlan,
  payloads: readonly T[],
): Array<Record<string, T>> {
  if (payloads.length !== plan.cases.length) {
    throw new Error(
      `v2ModelRows: expected one payload per fixture case (${plan.cases.length}), got ${payloads.length}`,
    )
  }

  const rows: Array<Record<string, T>> = Array.from(
    { length: plan.rowCount },
    () => ({}),
  )

  plan.cases.forEach((fixtureCase, i) => {
    const row = rows[fixtureCase.row]
    const payload = payloads[i]
    if (row === undefined || payload === undefined) {
      throw new Error(
        `v2ModelRows: no payload for ${fixtureCase.label} (row ${fixtureCase.row})`,
      )
    }
    row[fixtureCase.slug] = payload
  })

  return rows
}

/**
 * Plaintext axes that the plan neither covers nor declares unreachable.
 *
 * Non-empty means real coverage was lost without anyone saying so — a domain was
 * deferred that turned out to be the last one on its axis, or a new axis arrived
 * already deferred. Suites assert this is empty.
 */
export function v2UndeclaredCastAs(plan: V2FixturePlan): CastAs[] {
  const covered = new Set(plan.cases.map((fixtureCase) => fixtureCase.castAs))
  const undeclared = new Set<CastAs>()
  for (const [, spec] of catalogRows()) {
    if (covered.has(spec.castAs)) continue
    if (V2_UNREACHABLE_CAST_AS[spec.castAs] !== undefined) continue
    undeclared.add(spec.castAs)
  }
  return [...undeclared]
}
