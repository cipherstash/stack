/**
 * Ground truth for which EQL v3 domains produce a DynamoDB `__hmac` attribute.
 *
 * On DynamoDB, `encryptedDynamoDB` writes `<attr>__hmac` only when the encrypted
 * payload carries an `hm` equality term (the gate is `if (encryptPayload.hm)` in
 * `helpers.ts`). The FFI emits `hm` exactly when the column's `build()` config
 * carries the `unique` index, minted by `indexesForCapabilities`
 * (`eql/v3/columns.ts`): a column is `equality`-capable AND either not ordering
 * or text-cast. So `unique`-index presence per domain IS the ground truth for
 * `__hmac`, and this test pins it for EVERY `types.*` domain.
 *
 * It exists because the `skills/stash-dynamodb` doc makes a per-domain claim
 * about `__hmac` and nothing else checks it — skills ship to customers and drift
 * silently. If a domain's capabilities change, this fails and the doc's domain
 * table must be re-checked against it.
 *
 * Note the subtlety this locks: several `*Ord` domains are `equality`-capable
 * (they answer equality via an ordering term in Postgres) yet write NO `__hmac`,
 * because equality on DynamoDB needs the deterministic `hm`, which only the
 * `unique` index provides. "Equality-capable" is therefore NOT the same set as
 * "writes `__hmac`".
 */
import { describe, expect, it } from 'vitest'
import { types } from '@/eql/v3'

/**
 * The domains that mint an `hm` equality term, and so write `<attr>__hmac`:
 * every `*Eq`, plus the text-cast ordering/search domains (text equality is
 * always HMAC-based). Everything else — non-text `*Ord`/`*OrdOre`, the bare
 * storage-only domains, `TextMatch`, and `Json` — does not.
 */
const WRITES_HMAC = new Set<string>([
  'TextEq',
  'IntegerEq',
  'SmallintEq',
  'BigintEq',
  'DateEq',
  'TimestampEq',
  'NumericEq',
  'RealEq',
  'DoubleEq',
  'TextOrd',
  'TextOrdOre',
  'TextSearch',
])

/** Does this domain's column config carry the `unique` index (→ `hm` → `__hmac`)? */
function buildsUniqueIndex(factory: (name: string) => unknown): boolean {
  const column = factory('c') as {
    build(): { indexes: Record<string, unknown> }
  }
  return 'unique' in column.build().indexes
}

const allDomains = Object.keys(types) as Array<keyof typeof types>

describe('EQL v3 domain → __hmac ground truth', () => {
  it('covers every domain the skill can reference', () => {
    // Guard against a new domain being added without a verdict here.
    expect(allDomains.length).toBe(40)
  })

  it.each(allDomains)('%s matches the documented __hmac set', (name) => {
    const factory = types[name] as (n: string) => unknown
    expect(buildsUniqueIndex(factory)).toBe(WRITES_HMAC.has(name as string))
  })

  it('is exactly the 12 documented domains — no more, no fewer', () => {
    const actual = allDomains
      .filter((n) => buildsUniqueIndex(types[n] as (x: string) => unknown))
      .map((n) => n as string)
      .sort()

    expect(actual).toEqual([...WRITES_HMAC].sort())
    expect(actual).toHaveLength(12)
  })
})
