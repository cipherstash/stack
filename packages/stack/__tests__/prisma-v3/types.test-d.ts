import { describe, expectTypeOf, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import type { EncryptedWhere, SqlFragment } from '@/eql/v3/prisma'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  age: types.IntegerOrd('age'),
  createdOn: types.TimestampOrd('created_on'),
  active: types.Boolean('active'),
})

declare const where: EncryptedWhere

describe('where builder plaintext narrowing', () => {
  it('pins operand types to the column domain', () => {
    expectTypeOf(where.eq(users.email, 'a@b.com')).resolves.toEqualTypeOf<SqlFragment>()
    expectTypeOf(where.gt(users.age, 30)).resolves.toEqualTypeOf<SqlFragment>()
    expectTypeOf(
      where.between(users.createdOn, new Date(), new Date()),
    ).resolves.toEqualTypeOf<SqlFragment>()

    // @ts-expect-error — text column takes string, not number
    where.eq(users.email, 42)
    // @ts-expect-error — integer column takes number, not string
    where.gt(users.age, 'thirty')
    // @ts-expect-error — timestamp column takes Date
    where.lt(users.createdOn, 'yesterday')
    // @ts-expect-error — boolean column takes boolean
    where.eq(users.active, 'yes')
  })

  it('list operands follow the column type', () => {
    expectTypeOf(
      where.in(users.email, ['a', 'b']),
    ).resolves.toEqualTypeOf<SqlFragment>()
    // @ts-expect-error — numbers in a text column list
    where.in(users.email, [1, 2])
  })

  it('orderBy and null checks are synchronous fragments', () => {
    expectTypeOf(where.orderBy(users.age, 'desc')).toEqualTypeOf<SqlFragment>()
    expectTypeOf(where.isNull(users.email)).toEqualTypeOf<SqlFragment>()
  })
})
