/**
 * Live round-trip half of the type-driven v3 matrix — closes the "live cliff".
 *
 * The structural `matrix.test.ts` proves builder/eqlType/capabilities/`build()`
 * wiring for all 39 domains WITHOUT ever touching real FFI ciphertext. This file
 * completes the picture: every non-live-gated domain × every catalog `sample`
 * is encrypted and decrypted through a live CipherStash client, so those
 * domains gain live behavioral proof (the Rust harness's whole premise).
 * Domains with a catalog `liveGate` (currently the bigint family, pending the
 * next protect-ffi release) are excluded and reported as explicit skips.
 *
 * Round-trips go through the MODEL path (`encryptModel`/`decryptModel`) so
 * `reconstructRow` rebuilds `Date` values uniformly for every plaintext axis; a
 * lone single-value `decrypt` of a `date` domain returns an ISO string instead.
 *
 * The live work is BATCHED: one mega table spans every domain (one column each),
 * and the whole sample set round-trips in a single `bulkEncryptModels` +
 * `bulkDecryptModels` pair (2 network calls), not ~120 sequential ones. Error
 * samples (NaN/±Infinity) use the single-value path — the guard throws
 * client-side before any network — and so stay cheap even one at a time.
 */
import 'dotenv/config'
import { beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3, encryptedTable } from '@/encryption/v3'
import { unwrapResult } from '../fixtures'
import { describeLive, LIVE_CIPHERSTASH_ENABLED } from '../helpers/live-gate'
import {
  type DomainSpec,
  type EqlV3TypeName,
  typedEntries,
  V3_MATRIX,
} from './catalog'

/** `eql_v3.integer_ord` → `integer_ord`: a valid, per-domain-unique column name. */
const slug = (t: EqlV3TypeName): string => t.replace('eql_v3.', '')

// `as const satisfies Record<...>` gives `V3_MATRIX` a narrower type than
// `Record<EqlV3TypeName, DomainSpec>` (rows that omit the optional
// `errorSamples` field literally lack that key, rather than typing it
// `undefined`). Explicit type arguments pin `typedEntries`'s inferred `V` back
// to the declared `DomainSpec` shape — without them, `spec` below is inferred
// as the union of all the distinct row literals, and `.errorSamples` fails to
// resolve on members that omit the key (`tsc` catches this; `vitest run`
// alone would not, since it only transpiles `.test.ts` files, never
// typechecks them).
const allDomains = typedEntries<EqlV3TypeName, DomainSpec>(V3_MATRIX)

// Live-gated domains (currently the bigint family) are excluded from the mega
// table entirely — encrypting their samples through the installed protect-ffi
// throws at RUNTIME, which would fail the shared `beforeAll` and take every
// other domain's proof down with it. Each gets an explicit skip naming the
// gate instead (see `DomainSpec.liveGate`).
const domains = allDomains.filter(([, spec]) => !spec.liveGate)
const gatedDomains = allDomains.filter(([, spec]) => spec.liveGate)

// One mega table: one column per catalog domain. Column names (the slugs) are
// unique and never collide with `EncryptedTable` reserved property names.
const columns = Object.fromEntries(
  domains.map(([t, spec]) => [slug(t), spec.builder(slug(t))]),
)
const table = encryptedTable('v3_matrix_live', columns as never)

// Batch the samples into as few model rows as the widest sample set requires:
// row `i` carries every domain's `samples[i]` (domains with fewer samples are
// simply absent from later rows, and `encryptModel` skips absent fields).
const maxSamples = Math.max(...domains.map(([, spec]) => spec.samples.length))
const modelRows = Array.from({ length: maxSamples }, (_, i) => {
  const row: Record<string, unknown> = {}
  for (const [t, spec] of domains) {
    if (i < spec.samples.length) row[slug(t)] = spec.samples[i]
  }
  return row
})

// Flatten to one assertion per (domain, sample) — labelled so vitest reports the
// exact domain + sample index that fails.
const roundTripCases = domains.flatMap(([t, spec]) =>
  spec.samples.map((sample, i) => [`${t} #${i}`, slug(t), sample, i] as const),
)
const errorCases = domains.flatMap(([t, spec]) =>
  (spec.errorSamples ?? []).map(
    (bad) => [`${t} (${bad})`, slug(t), bad] as const,
  ),
)

describeLive('v3 matrix live round-trip (all domains × samples)', () => {
  let client: Awaited<ReturnType<typeof EncryptionV3>>
  let encrypted: Array<Record<string, unknown>>
  let decrypted: Array<Record<string, unknown>>

  beforeAll(async () => {
    client = await EncryptionV3({ schemas: [table] as never })
    encrypted = unwrapResult(
      await client.bulkEncryptModels(modelRows as never, table as never),
    ) as Array<Record<string, unknown>>
    decrypted = unwrapResult(
      await client.bulkDecryptModels(encrypted as never, table as never),
    ) as Array<Record<string, unknown>>
  }, 60000)

  it.each(
    roundTripCases,
  )('%s round-trips through the model path', (_label, col, sample, i) => {
    // Guard against a false pass: the field must be a real ciphertext (`c`),
    // not a plaintext value that slipped through un-encrypted.
    expect(encrypted[i][col]).toHaveProperty('c')

    const actual = decrypted[i][col]
    if (sample instanceof Date) {
      expect(actual).toBeInstanceOf(Date)
      expect(actual).toEqual(sample)
    } else {
      expect(actual).toStrictEqual(sample)
    }
  })

  // Mirrors number-protect.test.ts: NaN/±Infinity must be rejected. The guard
  // (encrypt.ts) throws client-side, so the single-value path is the honest place
  // to prove where the rejection fires.
  it.each(errorCases)('%s is rejected at encrypt', async (_label, col, bad) => {
    const column = (table as unknown as Record<string, unknown>)[col]
    const result = await client.encrypt(bad as never, {
      table: table as never,
      column: column as never,
    })
    expect(result.failure).toBeDefined()
  })

  // Live-gated domains: an explicit, reason-bearing skip per domain so the
  // vitest report shows exactly what is deferred and why, instead of the
  // domains silently vanishing from live coverage.
  if (gatedDomains.length > 0) {
    it.skip.each(
      gatedDomains,
    )('%s live round-trip (see skip reason in catalog liveGate)', () => {})
  }
})
