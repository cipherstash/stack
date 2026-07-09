import { describe, expectTypeOf, it } from 'vitest'
import type { types as v3Types } from '@/eql/v3'
import { types } from '@/eql/v3/drizzle/types'

describe('v3 drizzle types - type-level', () => {
  it('exposes exactly the same factory keys as @/eql/v3 types', () => {
    expectTypeOf<keyof typeof types>().toEqualTypeOf<keyof typeof v3Types>()
  })

  it('columns infer their concrete plaintext type via the data type slot', () => {
    const age = types.IntegerOrd('age')
    const ageEq = types.IntegerEq('age_eq')
    const smallint = types.SmallintOrd('smallint')
    const date = types.DateOrd('created_at')
    const dateOre = types.DateOrdOre('created_at_ore')
    const created = types.Timestamp('created_at')
    const tsOrd = types.TimestampOrd('created_at_ord')
    const numOre = types.NumericOrdOre('amount_ore')
    const flag = types.Boolean('flag')
    const nick = types.TextEq('nickname')
    const text = types.Text('text')
    const match = types.TextMatch('bio')
    const textOrd = types.TextOrd('text_ord')
    const textOrdOre = types.TextOrdOre('text_ord_ore')
    const search = types.TextSearch('search')
    const realEq = types.RealEq('real_eq')
    const doubleOrd = types.DoubleOrd('double_ord')

    expectTypeOf(age._.data).toEqualTypeOf<number>()
    expectTypeOf(ageEq._.data).toEqualTypeOf<number>()
    expectTypeOf(smallint._.data).toEqualTypeOf<number>()
    expectTypeOf(date._.data).toEqualTypeOf<Date>()
    expectTypeOf(dateOre._.data).toEqualTypeOf<Date>()
    expectTypeOf(created._.data).toEqualTypeOf<Date>()
    expectTypeOf(tsOrd._.data).toEqualTypeOf<Date>()
    expectTypeOf(numOre._.data).toEqualTypeOf<number>()
    expectTypeOf(flag._.data).toEqualTypeOf<boolean>()
    expectTypeOf(nick._.data).toEqualTypeOf<string>()
    expectTypeOf(text._.data).toEqualTypeOf<string>()
    expectTypeOf(match._.data).toEqualTypeOf<string>()
    expectTypeOf(textOrd._.data).toEqualTypeOf<string>()
    expectTypeOf(textOrdOre._.data).toEqualTypeOf<string>()
    expectTypeOf(search._.data).toEqualTypeOf<string>()
    expectTypeOf(realEq._.data).toEqualTypeOf<number>()
    expectTypeOf(doubleOrd._.data).toEqualTypeOf<number>()
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
