/**
 * Type-driven Supabase v3 wire sweep — every domain, every capability tier.
 *
 * The hand-written wire tests (`supabase-v3-builder.test.ts`) drive only five
 * of the catalog's 39 domains through `EncryptedQueryBuilderV3Impl`; the whole
 * numeric family never reached the adapter at all. This file closes that by
 * reusing the SAME compile-enforced catalog (`v3-matrix/catalog.ts`) the
 * Drizzle live suite tiers off, so adding a domain to the SDK yields a Supabase
 * wire assertion for free — or fails to compile until it does.
 *
 * Tiers are derived from `indexes` exactly as `drizzle-v3/operators-live-pg.
 * test.ts` derives them, rather than from `capabilities`. The adapter's guard
 * reads `capabilities`, so deriving the tier from the other field makes a
 * future capability/index divergence surface here as a tier mismatch instead of
 * silently agreeing with itself.
 *
 * Only the WIRE ENCODING is under test — the mock client records `{method,
 * args}` and no SQL runs. `supabase-v3-operators-live-pg.test.ts` is what
 * proves Postgres accepts what this file pins.
 */

import type { AnyV3Table } from '@cipherstash/stack/eql/v3'
import { encryptedTable } from '@cipherstash/stack/eql/v3'
import {
  type DomainSpec,
  type EqlV3TypeName,
  eqlTypeSlug as slug,
  typedEntries,
  V3_MATRIX,
} from '@cipherstash/test-kit/catalog'
import { describe, expect, it } from 'vitest'
import { EncryptedQueryBuilderV3Impl } from '../src/query-builder-v3'
import {
  createMockEncryptionClient,
  createMockSupabase,
  isFakeEnvelope,
} from './helpers/supabase-mock'

const matrixEntries = typedEntries(V3_MATRIX)

// Tiering, mirroring `drizzle-v3/operators-live-pg.test.ts`.
const equalityDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.unique || spec.indexes.ore || spec.indexes.ope,
)
const orderDomains = matrixEntries.filter(
  ([, spec]) => spec.indexes.ore || spec.indexes.ope,
)
const matchDomains = matrixEntries.filter(([, spec]) => spec.indexes.match)
/** No index at all — the `public.eql_v3_boolean`/`public.eql_v3_text`/… storage-only domains. */
const storageOnlyDomains = matrixEntries.filter(
  ([, spec]) =>
    !spec.indexes.unique &&
    !spec.indexes.ore &&
    !spec.indexes.ope &&
    !spec.indexes.match,
)

/**
 * One table per domain, property name == DB name (`builder(slug(eqlType))`) —
 * the shape introspection synthesizes. Renames are covered by the declared
 * `users` table in `supabase-v3-builder.test.ts`.
 */
function tableFor(eqlType: EqlV3TypeName, spec: DomainSpec): AnyV3Table {
  const name = slug(eqlType)
  return encryptedTable('matrix', {
    [name]: spec.builder(name),
  }) as unknown as AnyV3Table
}

function instanceFor(
  eqlType: EqlV3TypeName,
  spec: DomainSpec,
  resultData: unknown = [],
) {
  const supabase = createMockSupabase(resultData)
  const builder = new EncryptedQueryBuilderV3Impl(
    'matrix',
    tableFor(eqlType, spec),
    createMockEncryptionClient(),
    supabase.client,
    null,
  )
  // The typed surface is keyed by the declared row type; these tests address
  // columns by a runtime-computed slug and deliberately reach past it (the
  // storage-only tier exists to prove the RUNTIME guard fires).
  // biome-ignore lint/suspicious/noExplicitAny: see above
  return { q: builder as any, supabase, name: slug(eqlType) }
}

/** `samples[0]`, asserted non-null: a null operand short-circuits encryption
 * entirely (`isEncryptableTerm`), so a future null sample would silently turn
 * the capability-guard tier below into a no-op that passes for the wrong
 * reason. Fail loudly instead. */
function firstSample(spec: DomainSpec): unknown {
  const sample = spec.samples[0]
  expect(sample).not.toBeNull()
  expect(sample).not.toBeUndefined()
  return sample
}

/** A free-text needle that clears the tokenizer's token_length floor. The text
 * catalog's `samples[0]` is the empty string (a stored-value edge case), which
 * the matches() short-needle guard now correctly REJECTS — so the wire tests
 * for matches()/like() need a real, tokenizable needle instead. */
function matchNeedle(spec: DomainSpec): string {
  const needle = spec.samples.find(
    (s): s is string => typeof s === 'string' && [...s].length >= 3,
  )
  expect(needle).toBeDefined()
  return needle as string
}

describe('supabase v3 wire encoding, every domain', () => {
  // Guards the tier arithmetic itself. A domain silently dropping out of a
  // tier would otherwise just shrink an `it.each` with no test turning red.
  it('tiers all 40 domains', () => {
    expect(matrixEntries).toHaveLength(40)
    expect(equalityDomains).toHaveLength(28)
    expect(orderDomains).toHaveLength(19)
    expect(matchDomains).toHaveLength(2)
    // +1: `eql_v3_json` carries only an `ste_vec` index, so from this scalar
    // tiering it reads as storage-only — the Supabase adapter has no JSON
    // containment path (PostgREST can't cast/call), so it rejects scalar ops.
    expect(storageOnlyDomains).toHaveLength(11)
  })

  describe.each(matrixEntries)('%s', (eqlType, spec) => {
    it('inserts a raw envelope keyed by the column name (no composite wrap)', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.insert({ [name]: firstSample(spec) })

      const [insert] = supabase.callsFor('insert')
      const body = insert.args[0] as Record<string, unknown>
      expect(Object.keys(body)).toEqual([name])
      expect(isFakeEnvelope(body[name])).toBe(true)
      // v2 wraps in `{ data: … }`; the v3 domains are `DOMAIN … AS jsonb`.
      expect((body[name] as Record<string, unknown>).data).toBeUndefined()
    })

    it('adds a ::jsonb cast in select', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.select(`id, ${name}`)

      expect(supabase.callsFor('select')[0].args[0]).toBe(`id, ${name}::jsonb`)
    })
  })

  describe.each(equalityDomains)('%s (equality)', (eqlType, spec) => {
    it('encrypts an eq() operand as a full-envelope jsonb string', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.select(`id, ${name}`).eq(name, firstSample(spec))

      const [eq] = supabase.callsFor('eq')
      expect(eq.args[0]).toBe(name)
      // The FULL storage envelope, not a narrowed `encryptQuery` term: the
      // `public.*` domain CHECK requires `v`/`i`/`c`.
      expect(JSON.parse(eq.args[1] as string).c).toBeDefined()
    })
  })

  describe.each(orderDomains)('%s (orderAndRange)', (eqlType, spec) => {
    it('encrypts a gte() operand as a full-envelope jsonb string', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.select(`id, ${name}`).gte(name, firstSample(spec))

      const [gte] = supabase.callsFor('gte')
      expect(gte.args[0]).toBe(name)
      expect(JSON.parse(gte.args[1] as string).c).toBeDefined()
    })

    // A bare `ORDER BY col` WOULD be wrong — no btree operator class exists on
    // any EQL v3 domain, so it falls through to jsonb's default opclass and
    // sorts the ciphertext envelope. The builder never emits one. For an
    // OPE-backed column it emits the jsonb path `col->>op`, which selects the
    // order-preserving term. For an ORE-backed column there is no such path —
    // `ob` is an array of blocks needing the superuser-only comparator — so it
    // is refused.
    if (spec.indexes.ope) {
      it('orders by the OPE term, not by the envelope', async () => {
        const { q, supabase, name } = instanceFor(eqlType, spec)

        const { error } = await q.select(`id, ${name}`).order(name)

        expect(error).toBeNull()
        const [order] = supabase.callsFor('order')
        expect(order.args[0]).toBe(`${name}->op`)
      })
    } else {
      it('rejects order() even though gte() is supported', async () => {
        const { q, supabase, name } = instanceFor(eqlType, spec)

        const { error, status } = await q.select(`id, ${name}`).order(name)

        expect(status).toBe(500)
        expect(error?.message).toContain('cannot order by encrypted column')
        expect(error?.message).toContain('ORE ordering term')
        expect(supabase.callsFor('order')).toHaveLength(0)
      })
    }
  })

  describe.each(matchDomains)('%s (freeTextSearch)', (eqlType, spec) => {
    it('emits matches() as a cs containment filter', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.select(`id, ${name}`).matches(name, matchNeedle(spec))

      const [filter] = supabase.callsFor('filter')
      expect(filter.args[0]).toBe(name)
      expect(filter.args[1]).toBe('cs')
      expect(JSON.parse(filter.args[2] as string).c).toBeDefined()
      // The v3 domains define no LIKE operator — a bare `like` would 42883.
      expect(supabase.callsFor('like')).toHaveLength(0)
    })

    it('refuses contains(), directing the caller to matches()', async () => {
      const { q, name } = instanceFor(eqlType, spec)

      expect(() => q.contains(name, firstSample(spec))).toThrow(
        /Use matches\(\)/,
      )
    })

    // like/ilike on an encrypted free-text column are an approximate shim that
    // DELEGATES to matches: a wildcard-free sample is fuzzy-matched, emitting the
    // same `cs` wire as matches() (#617). (These matrix samples carry no `%`/`_`.)
    it('delegates like() to matches, emitting the same cs filter', async () => {
      const { q, supabase, name } = instanceFor(eqlType, spec)

      await q.select(`id, ${name}`).like(name, matchNeedle(spec))

      const [filter] = supabase.callsFor('filter')
      expect(filter.args[0]).toBe(name)
      expect(filter.args[1]).toBe('cs')
      expect(JSON.parse(filter.args[2] as string).c).toBeDefined()
      expect(supabase.callsFor('like')).toHaveLength(0)
    })
  })

  describe.each(storageOnlyDomains)('%s (storage only)', (eqlType, spec) => {
    it('rejects eq() with the equality capability message', async () => {
      const { q, name } = instanceFor(eqlType, spec)

      const { error, status } = await q.select('id').eq(name, firstSample(spec))

      expect(status).toBe(500)
      expect(error?.message).toContain('does not support equality')
    })

    it('rejects gte() with the orderAndRange capability message', async () => {
      const { q, name } = instanceFor(eqlType, spec)

      const { error, status } = await q
        .select('id')
        .gte(name, firstSample(spec))

      expect(status).toBe(500)
      expect(error?.message).toContain('does not support orderAndRange')
    })

    it('rejects order() with the encrypted-ordering message', async () => {
      const { q, name } = instanceFor(eqlType, spec)

      const { error, status } = await q.select('id').order(name)

      expect(status).toBe(500)
      expect(error?.message).toContain('cannot order by encrypted column')
    })
  })
})
