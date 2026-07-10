import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { IntegrationAdapter } from './adapter.ts'
import type { DomainSpec } from './catalog.ts'
import { domainsForFamily, type FamilyName } from './families.ts'
import { negativeOps, type Plain, positiveOps, type QueryOp } from './ops.ts'
import {
  comparePlain,
  containsPlain,
  expectedKeysFor,
  plainValue,
  sortedKeysFor,
} from './oracle.ts'
import { planRows, planTable } from './rows.ts'

/**
 * The shared driver. One family file per adapter is three lines; everything a
 * test asserts is derived from the domain's catalog row, so Drizzle and Supabase
 * cannot quietly cover different operations while both read as "comprehensive".
 *
 * What is asserted, per domain:
 * - every operation the domain's capabilities allow, over a RANGE of values,
 *   against a plaintext oracle;
 * - every operation they forbid, rejected;
 * - that both the single-encrypt and bulk-encrypt insert paths produced
 *   queryable ciphertext.
 */

/** Distinct sample values for a domain, in ascending order, deduplicated by `comparePlain`. */
function distinctValues(spec: DomainSpec, rowKeys: readonly string[]): Plain[] {
  const values = rowKeys.map((key) => plainValue(spec, rowKeys, key))
  const sorted = [...values].sort(comparePlain)
  return sorted.filter(
    (value, i) => i === 0 || comparePlain(value, sorted[i - 1] as Plain) !== 0,
  )
}

/** A needle to search for, and what it is meant to discriminate. */
type Needle = Readonly<{ label: string; needle: string }>

/**
 * The needle set for a `freeTextSearch` domain.
 *
 * A single 3-character needle is NOT sufficient coverage, and the reason is
 * subtle enough to be worth stating.
 *
 * The match index tokenizes into downcased 3-grams. `include_original: true`
 * additionally blooms the WHOLE value as one token. Storage wants that; a QUERY
 * operand must not have it, or the needle's bloom carries a whole-needle token
 * that the haystack's bloom cannot contain, and every strict-substring search
 * returns nothing.
 *
 * Both v3 adapters build match operands with `encrypt` — the full storage
 * envelope — not `encryptQuery`, because PostgREST cannot cast a filter value to
 * `eql_v3.query_*`. So both are structurally exposed to exactly that. Today it
 * is masked: protect-ffi ignores `include_original` outright, so neither the
 * stored value nor the operand carries the whole-value token. Two bugs cancel.
 * The day protect-ffi honours the flag, substring search breaks — silently, by
 * returning no rows. See cipherstash/stack#615.
 *
 * A 3-character needle cannot see any of this: its whole-value token IS a
 * trigram, so it matches either way. That is the degenerate case. The
 * discriminating needle is a strict substring LONGER than `token_length`, taken
 * from the interior so no prefix-specific shortcut can satisfy it.
 *
 * THROWS rather than skipping when no sample qualifies: a `freeTextSearch`
 * domain whose catalog row cannot produce a needle is a catalog bug, and must be
 * loud. (This previously derived the needle from the domain's MINIMUM value —
 * the empty string for text — so `text_match`, the only match-only domain,
 * silently skipped the only test of its only capability.)
 */
function needlesFrom(values: readonly Plain[]): Needle[] {
  const longest = [...values]
    .map(String)
    .sort((left, right) => right.length - left.length)[0]

  if (longest === undefined || longest.length < 3) {
    throw new Error(
      'No sample is long enough to build an answerable needle (>= token_length 3). ' +
        'A freeTextSearch domain must carry at least one such sample in the catalog.',
    )
  }

  const value = longest.toLowerCase()
  const needles: Needle[] = [
    // Degenerate: exactly one trigram. Matches whether or not `include_original`
    // is honoured, because the whole needle IS a trigram.
    { label: 'a 3-character needle (one trigram)', needle: value.slice(0, 3) },
    // The whole stored value. Matches under either behaviour.
    { label: 'the whole stored value', needle: value },
    // Absent from every sample, so it must never match. Guards against a
    // predicate that ignores its operand — and against a bloom false positive
    // being mistaken for coverage.
    { label: 'a needle absent from every value', needle: 'qqqzzz' },
  ]

  // The discriminating case: a strict substring longer than one trigram, drawn
  // from the interior. Fails the moment a whole-needle token enters the operand.
  if (value.length >= 6) {
    needles.splice(1, 0, {
      label: 'a strict interior substring longer than one trigram',
      needle: value.slice(2, Math.min(value.length - 1, 8)),
    })
  }

  return needles
}

/** A representative operand for a rejected operation — the value never reaches the DB. */
function sampleOpFor(
  kind: QueryOp['kind'],
  column: string,
  value: Plain,
): QueryOp {
  switch (kind) {
    case 'in':
    case 'notIn':
      return { kind, column, values: [value] }
    case 'between':
    case 'notBetween':
      return { kind, column, lo: value, hi: value }
    case 'contains':
      return {
        kind,
        column,
        needle:
          String(value).length >= 3
            ? String(value).slice(0, 3).toLowerCase()
            : 'abc',
      }
    case 'order':
      return { kind, column, direction: 'asc' }
    case 'isNull':
    case 'isNotNull':
      return { kind, column }
    default:
      return { kind, column, value }
  }
}

export function runFamilySuite(
  family: FamilyName,
  makeAdapter: () => IntegrationAdapter,
): void {
  const adapter = makeAdapter()
  const domains = domainsForFamily(family)

  // Unique per run so a crashed run never leaves a table that shadows the next.
  const runId = Math.random().toString(36).slice(2, 8)
  const table = planTable(family, domains, runId)
  const plan = planRows(domains, runId)
  const { rowKeys, byKey } = plan

  describe(`v3 ${adapter.name} — ${family}`, () => {
    beforeAll(async () => {
      await adapter.setup()
      await adapter.createTable(table)

      // Disjoint, interleaved halves: any predicate matching more than one row
      // necessarily spans both encryption paths.
      for (const key of plan.singleKeys) {
        await adapter.insertSingle(table, byKey[key] as never)
      }
      await adapter.insertBulk(
        table,
        plan.bulkKeys.map((key) => byKey[key] as never),
      )
      // Every encrypted column NULL. Goes through the single path; the bulk path
      // is already proven by the value rows.
      await adapter.insertSingle(table, plan.nullRow)
    }, 300_000)

    afterAll(async () => {
      await adapter.teardown()
    })


    for (const domain of domains) {
      describe(domain.bare, () => {
        const { slug, spec } = domain
        const values = distinctValues(spec, rowKeys)
        const min = values[0] as Plain
        const max = values[values.length - 1] as Plain

        const positive = positiveOps(spec.capabilities, adapter.supportedOps)
        const negative = negativeOps(spec.capabilities, adapter.supportedOps)

        const expectRows = async (op: QueryOp, expected: string[]) => {
          const rows = await adapter.run(table, op)
          expect([...rows].sort()).toEqual([...expected].sort())
        }

        const keysWhere = (predicate: (value: Plain) => boolean) =>
          expectedKeysFor(spec, rowKeys, predicate)

        if (positive.has('eq')) {
          it.each(values)('eq(%s) selects exactly its rows', async (value) => {
            await expectRows(
              { kind: 'eq', column: slug, value },
              keysWhere((v) => comparePlain(v, value) === 0),
            )
          })
        }

        if (positive.has('ne')) {
          it('ne excludes exactly its rows', async () => {
            await expectRows(
              { kind: 'ne', column: slug, value: min },
              keysWhere((v) => comparePlain(v, min) !== 0),
            )
          })
        }

        if (positive.has('in')) {
          // Adapters with a second `in`-list code path drive both against the
          // same oracle. See `IntegrationAdapter.hasRawInListPath`.
          const variants = adapter.hasRawInListPath ? [false, true] : [false]
          for (const asRawFilter of variants) {
            const label = asRawFilter ? 'filter(in)' : 'in()'

            it(`${label} selects the union of the listed values`, async () => {
              const listed = values.slice(0, 2)
              await expectRows(
                { kind: 'in', column: slug, values: listed, asRawFilter },
                keysWhere((v) => listed.some((l) => comparePlain(v, l) === 0)),
              )
            })

            it(`${label} excludes rows whose value is absent from the list`, async () => {
              // Guards against a predicate that matches everything: without this,
              // a filter that ignored its operand would pass the test above.
              await expectRows(
                { kind: 'in', column: slug, values: [min], asRawFilter },
                keysWhere((v) => comparePlain(v, min) === 0),
              )
            })
          }
        }

        if (positive.has('notIn')) {
          it('notIn excludes the listed values', async () => {
            await expectRows(
              { kind: 'notIn', column: slug, values: [min] },
              keysWhere((v) => comparePlain(v, min) !== 0),
            )
          })
        }

        for (const kind of ['gt', 'gte', 'lt', 'lte'] as const) {
          if (!positive.has(kind)) continue
          it.each([
            min,
            max,
          ])(`${kind}(%s) matches the oracle`, async (bound) => {
            const cmp = {
              gt: (c: number) => c > 0,
              gte: (c: number) => c >= 0,
              lt: (c: number) => c < 0,
              lte: (c: number) => c <= 0,
            }[kind]
            await expectRows(
              { kind, column: slug, value: bound },
              keysWhere((v) => cmp(comparePlain(v, bound))),
            )
          })
        }

        if (positive.has('between')) {
          it('between(min, max) spans every row', async () => {
            await expectRows(
              { kind: 'between', column: slug, lo: min, hi: max },
              [...rowKeys],
            )
          })

          it('between(v, v) selects only that value', async () => {
            await expectRows(
              { kind: 'between', column: slug, lo: min, hi: min },
              keysWhere((v) => comparePlain(v, min) === 0),
            )
          })
        }

        if (positive.has('notBetween')) {
          it('notBetween(min, max) selects nothing', async () => {
            await expectRows(
              { kind: 'notBetween', column: slug, lo: min, hi: max },
              [],
            )
          })
        }

        if (positive.has('contains')) {
          it.each(needlesFrom(values))('contains: $label', async ({
            needle,
          }) => {
            await expectRows(
              { kind: 'contains', column: slug, needle },
              keysWhere((v) => containsPlain(v, needle)),
            )
          })
        }

        if (positive.has('order')) {
          it.each([
            'asc',
            'desc',
          ] as const)('order(%s) returns rows in plaintext order', async (direction) => {
            // Order is the one operation whose ROW ORDER is the assertion, so
            // it does not go through `expectRows` (which sorts both sides).
            const rows = await adapter.run(table, {
              kind: 'order',
              column: slug,
              direction,
            })
            expect(rows).toEqual(sortedKeysFor(spec, rowKeys, direction))
          })
        }

        // Structural, never capability-gated: a NULL plaintext is a SQL NULL on
        // every domain, storage-only ones included.
        it('isNull selects only the all-null row', async () => {
          await expectRows({ kind: 'isNull', column: slug }, ['null'])
        })

        it('isNotNull selects every value row', async () => {
          await expectRows({ kind: 'isNotNull', column: slug }, [...rowKeys])
        })

        // Proves BOTH encryption paths produced queryable ciphertext. The eq
        // loop above already spans them, but only implicitly; assert it.
        it('both encrypt paths produced queryable ciphertext', async () => {
          const rows = await adapter.run(table, {
            kind: 'isNotNull',
            column: slug,
          })
          expect(rows).toEqual(expect.arrayContaining([...plan.singleKeys]))
          expect(rows).toEqual(expect.arrayContaining([...plan.bulkKeys]))
        })

        for (const kind of negative) {
          it(`rejects ${kind}: not supported by this domain's capabilities`, async () => {
            await adapter.expectRejected(table, sampleOpFor(kind, slug, min))
          })
        }

        for (const kind of adapter.alwaysRejectedOps) {
          if (negative.has(kind)) continue // already covered above
          it(`rejects ${kind}: refused on every encrypted column by this adapter`, async () => {
            await adapter.expectRejected(table, sampleOpFor(kind, slug, min))
          })
        }
      })
    }
  })
}
