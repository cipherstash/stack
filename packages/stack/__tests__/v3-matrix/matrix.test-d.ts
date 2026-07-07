/**
 * Type-level half of the type-driven v3 matrix.
 *
 * Runtime `.each` cannot parameterise a compile-time `expectTypeOf<T>()` by row
 * data, so the type-level surface is asserted against a concrete mixed-tier
 * table. The columns under test are constructed FROM the `V3_MATRIX` builders
 * (via specific keys) rather than hand-copied — `as const satisfies` preserves
 * each builder's precise return type, so one catalog genuinely drives both the
 * runtime and type-level surfaces.
 *
 * Runs via `pnpm test:types` (picked up by the `.test-d.ts` typecheck glob).
 */
import { describe, expectTypeOf, it } from 'vitest'
import {
  encryptedTable,
  type InferPlaintext,
  type QueryableColumnsOf,
  type QueryTypesForColumn,
} from '@/eql/v3'
import { type EqlV3TypeName, V3_MATRIX } from './catalog'

// One mixed-tier table spanning every capability tier + plaintext axis, built
// from the catalog's own builders.
const records = encryptedTable('records', {
  count: V3_MATRIX['eql_v3.int4'].builder('count'), // number, storage-only
  score: V3_MATRIX['eql_v3.int4_eq'].builder('score'), // number, equality
  rank: V3_MATRIX['eql_v3.int4_ord'].builder('rank'), // number, order + range
  createdAt: V3_MATRIX['eql_v3.timestamp_ord'].builder('created_at'), // date
  email: V3_MATRIX['eql_v3.text_search'].builder('email'), // string, full-text
  active: V3_MATRIX['eql_v3.bool'].builder('active'), // boolean, storage-only
})

describe('eql_v3 type-driven matrix (types)', () => {
  it('maps each column to its plaintext axis', () => {
    expectTypeOf<InferPlaintext<typeof records>>().toEqualTypeOf<{
      count: number
      score: number
      rank: number
      createdAt: Date
      email: string
      active: boolean
    }>()
  })

  it('derives the queryType union per column from its capabilities', () => {
    expectTypeOf<
      QueryTypesForColumn<typeof records.count>
    >().toEqualTypeOf<never>()
    expectTypeOf<
      QueryTypesForColumn<typeof records.score>
    >().toEqualTypeOf<'equality'>()
    expectTypeOf<QueryTypesForColumn<typeof records.rank>>().toEqualTypeOf<
      'equality' | 'orderAndRange'
    >()
    expectTypeOf<QueryTypesForColumn<typeof records.createdAt>>().toEqualTypeOf<
      'equality' | 'orderAndRange'
    >()
    expectTypeOf<QueryTypesForColumn<typeof records.email>>().toEqualTypeOf<
      'equality' | 'orderAndRange' | 'freeTextSearch'
    >()
    expectTypeOf<
      QueryTypesForColumn<typeof records.active>
    >().toEqualTypeOf<never>()
  })

  it('excludes storage-only columns from the queryable set', () => {
    type Queryable = QueryableColumnsOf<typeof records>

    // A queryable column is a member of the set...
    const ok: Queryable = V3_MATRIX['eql_v3.int4_eq'].builder('score')
    expectTypeOf(ok).toExtend<Queryable>()

    // ...but a storage-only column is not.
    // @ts-expect-error - storage-only int4 column is excluded from QueryableColumnsOf
    const _notQueryable: Queryable = V3_MATRIX['eql_v3.int4'].builder('count')

    // @ts-expect-error - storage-only bool column is excluded from QueryableColumnsOf
    const _boolNotQueryable: Queryable =
      V3_MATRIX['eql_v3.bool'].builder('active')
  })

  it('anchors the catalog key union to the real column source of truth', () => {
    // `EqlV3TypeName` is derived from `AnyEncryptedV3Column`, so every real
    // domain name is a member — no hand-copied list.
    expectTypeOf<'eql_v3.text_search'>().toExtend<EqlV3TypeName>()
    expectTypeOf<'eql_v3.bool'>().toExtend<EqlV3TypeName>()

    // A key outside the real domain set is rejected — this is what makes the
    // `Record<EqlV3TypeName, DomainSpec>` catalog a compile-time coverage check.
    const bad: Partial<Record<EqlV3TypeName, number>> = {
      // @ts-expect-error - 'eql_v3.nope' is not a member of EqlV3TypeName
      'eql_v3.nope': 1,
    }
    void bad
  })
})
