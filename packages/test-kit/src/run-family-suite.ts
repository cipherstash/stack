import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { IntegrationAdapter } from './adapter.ts'
import type { DomainSpec } from './catalog.ts'
import {
  deferredForFamily,
  domainsForFamily,
  type FamilyDomain,
  type FamilyName,
} from './families.ts'
import { negativeOps, type Plain, positiveOps, type QueryOp } from './ops.ts'
import {
  comparePlain,
  containsPlain,
  expectedKeysFor,
  plainValue,
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

/**
 * A needle guaranteed to be answerable: the first three characters of the first
 * sample long enough to produce one, downcased. `token_length` is 3, so a
 * shorter needle blooms to nothing and the adapters reject it — see
 * `requireAnswerableNeedle`.
 *
 * THROWS rather than skipping when no sample qualifies. It previously derived
 * the needle from the domain's MINIMUM value, which for the text samples is the
 * empty string — so `text_match`, the only match-only domain, silently skipped
 * the only test that exercises its one capability. A `freeTextSearch` domain
 * whose catalog row cannot produce a needle is a catalog bug, and must be loud.
 */
function needleFrom(values: readonly Plain[]): string {
  for (const value of values) {
    const text = String(value)
    if (text.length >= 3) return text.slice(0, 3).toLowerCase()
  }
  throw new Error(
    'No sample is long enough to build an answerable needle (>= token_length 3). ' +
      'A freeTextSearch domain must carry at least one such sample in the catalog.',
  )
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
  const deferred = deferredForFamily(family)

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

    if (deferred.length > 0) {
      it.skip(`defers ${deferred.map((d) => d.bare).join(', ')}: ${deferred[0]?.reason}`, () => {})
    }

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
          // Both the `in()` method and the raw `filter(col, 'in', [...])` path:
          // they are different code paths, and the raw one encrypted the whole
          // list as a single term until recently.
          for (const asRawFilter of [false, true]) {
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
          const needle = needleFrom(values)
          it('contains matches the rows whose plaintext contains the needle', async () => {
            await expectRows(
              { kind: 'contains', column: slug, needle },
              keysWhere((v) => containsPlain(v, needle)),
            )
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
