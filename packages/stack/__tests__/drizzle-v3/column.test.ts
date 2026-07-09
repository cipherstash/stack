import { pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { types as v3Types } from '@/eql/v3'
import {
  EQL_V3_DOMAINS,
  getEqlV3Column,
  isEqlV3Column,
  makeEqlV3Column,
} from '@/eql/v3/drizzle/column'
import { typedEntries, V3_MATRIX } from '../v3-matrix/catalog'

const slug = (eqlType: string) => eqlType.replace(/^public\./, '')

describe('makeEqlV3Column', () => {
  it('sets dataType() to the concrete eql_v3 domain', () => {
    const col = makeEqlV3Column(v3Types.IntegerOrd('age'))
    const table = pgTable('users', { age: col })

    expect(table.age.getSQLType()).toBe('public.integer_ord')
  })

  it('recovers the stashed builder before and after pgTable processing', () => {
    const col = makeEqlV3Column(v3Types.TextEq('nickname'))
    expect(isEqlV3Column(col)).toBe(true)
    expect(getEqlV3Column('nickname', col)?.getEqlType()).toBe('public.text_eq')

    const t = pgTable('users', { nickname: col })
    expect(getEqlV3Column('nickname', t.nickname)?.getEqlType()).toBe(
      'public.text_eq',
    )
  })

  it('EQL_V3_DOMAINS contains every concrete domain', () => {
    const all = Object.values(v3Types).map((f) => f('x').getEqlType())
    for (const domain of all) expect(EQL_V3_DOMAINS.has(domain)).toBe(true)
  })

  it('isEqlV3Column is false for a plain value', () => {
    expect(isEqlV3Column({})).toBe(false)
  })

  it('recognises v3 columns by the Drizzle getSQLType API', () => {
    expect(
      isEqlV3Column({
        getSQLType: () => 'public.text_eq',
      }),
    ).toBe(true)
  })

  it('recovers a v3 builder for columns recognised by getSQLType', () => {
    const builder = getEqlV3Column('nickname', {
      getSQLType: () => 'public.text_eq',
    })

    expect(builder?.getName()).toBe('nickname')
    expect(builder?.getEqlType()).toBe('public.text_eq')
  })

  it('recognises v3 columns by dataType() when getSQLType is absent', () => {
    const column = { dataType: () => 'public.text_eq' }
    const builder = getEqlV3Column('nickname', column)

    expect(isEqlV3Column(column)).toBe(true)
    expect(builder?.getName()).toBe('nickname')
    expect(builder?.getEqlType()).toBe('public.text_eq')
  })

  it('recognises v3 columns by sqlName when getSQLType is absent', () => {
    const column = { sqlName: 'public.integer_ord' }
    const builder = getEqlV3Column('age', column)

    expect(isEqlV3Column(column)).toBe(true)
    expect(builder?.getName()).toBe('age')
    expect(builder?.getEqlType()).toBe('public.integer_ord')
  })

  it.each(
    typedEntries(V3_MATRIX),
  )('%s round-trips through makeEqlV3Column and pgTable', (eqlType, spec) => {
    const columnName = slug(eqlType)
    const builder = spec.builder(columnName)
    const column = makeEqlV3Column(builder)

    expect(builder.getEqlType()).toBe(eqlType)
    expect(builder).toBeInstanceOf(spec.ColumnClass)
    expect(isEqlV3Column(column)).toBe(true)
    expect(getEqlV3Column(columnName, column)?.getEqlType()).toBe(eqlType)

    const table = pgTable('users', { [columnName]: column } as never)
    const pgColumn = (table as Record<string, { getSQLType(): string }>)[
      columnName
    ]
    expect(pgColumn?.getSQLType()).toBe(eqlType)
    expect(getEqlV3Column(columnName, pgColumn)?.getEqlType()).toBe(eqlType)
  })
})
