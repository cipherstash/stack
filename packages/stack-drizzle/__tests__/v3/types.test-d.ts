import type { types as v3Types } from '@cipherstash/stack/eql/v3'
import type { Encrypted } from '@cipherstash/stack/types'
import { describe, expectTypeOf, it } from 'vitest'
import { types } from '../../src/v3/types'

describe('v3 drizzle types - type-level', () => {
  it('exposes exactly the same factory keys as @/eql/v3 types', () => {
    expectTypeOf<keyof typeof types>().toEqualTypeOf<keyof typeof v3Types>()
  })

  it('types the data slot as the encrypted envelope, not plaintext (A3)', () => {
    // The value stored/inserted/selected is the ENCRYPTED EQL v3 jsonb envelope,
    // NOT the column's plaintext. So every concrete domain — regardless of its
    // plaintext axis (number/Date/boolean/string) — exposes `Encrypted` in its
    // Drizzle `data` slot. Plaintext inference is a separate concern, proven on
    // the v3 core builder via `PlaintextForColumn` (see schema-v3.test-d.ts).
    expectTypeOf(types.IntegerOrd('age')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.IntegerEq('age_eq')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.BigintOrd('big')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.DateOrd('created_at')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.Timestamp('ts')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.Boolean('flag')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.TextEq('nickname')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.TextSearch('search')._.data).toEqualTypeOf<Encrypted>()
    expectTypeOf(types.DoubleOrd('d')._.data).toEqualTypeOf<Encrypted>()
  })

  it('does not expose obsolete pre-0.27 concrete domain names', () => {
    // @ts-expect-error - use IntegerOrd
    types.Int4Ord('age')
    // @ts-expect-error - use SmallintOrd
    types.Int2Ord('age')
    // @ts-expect-error - use Timestamp
    types.Timestamptz('created_at')
    // @ts-expect-error - use Boolean
    types.Bool('active')
    // @ts-expect-error - use RealEq
    types.Float4Eq('score')
    // @ts-expect-error - use DoubleOrd
    types.Float8Ord('score')
  })
})
