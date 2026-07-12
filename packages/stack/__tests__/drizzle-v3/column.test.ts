import { pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { types as v3Types } from '@/eql/v3'
import {
  EQL_V3_DOMAINS,
  getEqlV3Column,
  isEqlV3Column,
  makeEqlV3Column,
} from '@/eql/v3/drizzle/column'
import {
  EQL_V3_DOMAIN_SCHEMA,
  eqlTypeSlug as slug,
  typedEntries,
  V3_MATRIX,
} from '../v3-matrix/catalog'

describe('makeEqlV3Column', () => {
  it('sets dataType() to the concrete eql_v3 domain', () => {
    const col = makeEqlV3Column(v3Types.IntegerOrd('age'))
    const table = pgTable('users', { age: col })

    expect(table.age.getSQLType()).toBe('public.eql_v3_integer_ord')
  })

  it('recovers the stashed builder before and after pgTable processing', () => {
    const col = makeEqlV3Column(v3Types.TextEq('nickname'))
    expect(isEqlV3Column(col)).toBe(true)
    expect(getEqlV3Column('nickname', col)?.getEqlType()).toBe(
      'public.eql_v3_text_eq',
    )

    const t = pgTable('users', { nickname: col })
    expect(getEqlV3Column('nickname', t.nickname)?.getEqlType()).toBe(
      'public.eql_v3_text_eq',
    )
  })

  it('stashes the builder under a single symbol key, with no string twin', () => {
    const symbol = Symbol.for('cipherstash:eqlv3Column')
    const carrierOf = (column: unknown) =>
      (column as { config?: { customTypeParams?: Record<string, unknown> } })
        .config?.customTypeParams

    const col = makeEqlV3Column(v3Types.TextEq('nickname'))
    const table = pgTable('users', { nickname: col })

    // `pgTable` builds a NEW PgColumn that does not carry the symbol directly —
    // it reaches the builder only through the shared `config.customTypeParams`.
    // That is the carrier the operators actually resolve through, so assert on
    // it specifically rather than on "some carrier somewhere".
    const pgCarrier = carrierOf(table.nickname)
    expect(pgCarrier).toBeDefined()
    expect(symbol in (pgCarrier as object)).toBe(true)
    expect(getEqlV3Column('nickname', table.nickname)?.getEqlType()).toBe(
      'public.eql_v3_text_eq',
    )

    // ...and no carrier keeps a redundant string twin of the symbol key.
    for (const carrier of [col, carrierOf(col), table.nickname]) {
      expect(carrier).toBeDefined()
      expect('_eqlv3Column' in (carrier as object)).toBe(false)
    }
  })

  it('every matrix domain slugs to a bare, dot-free column identifier', () => {
    // Guards the shared slug against drifting from the real domain schema: if
    // the domains move, the prefix constant must move with them or the slug
    // silently leaks a qualified name into the generated DDL.
    for (const [eqlType] of typedEntries(V3_MATRIX)) {
      expect(eqlType.startsWith(`${EQL_V3_DOMAIN_SCHEMA}.`)).toBe(true)
      expect(slug(eqlType)).not.toContain('.')
    }
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
        getSQLType: () => 'public.eql_v3_text_eq',
      }),
    ).toBe(true)
  })

  it('recovers a v3 builder for columns recognised by getSQLType', () => {
    const builder = getEqlV3Column('nickname', {
      getSQLType: () => 'public.eql_v3_text_eq',
    })

    expect(builder?.getName()).toBe('nickname')
    expect(builder?.getEqlType()).toBe('public.eql_v3_text_eq')
  })

  it('recognises v3 columns by dataType() when getSQLType is absent', () => {
    const column = { dataType: () => 'public.eql_v3_text_eq' }
    const builder = getEqlV3Column('nickname', column)

    expect(isEqlV3Column(column)).toBe(true)
    expect(builder?.getName()).toBe('nickname')
    expect(builder?.getEqlType()).toBe('public.eql_v3_text_eq')
  })

  it('recognises v3 columns by sqlName when getSQLType is absent', () => {
    const column = { sqlName: 'public.eql_v3_integer_ord' }
    const builder = getEqlV3Column('age', column)

    expect(isEqlV3Column(column)).toBe(true)
    expect(builder?.getName()).toBe('age')
    expect(builder?.getEqlType()).toBe('public.eql_v3_integer_ord')
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

  // The `toDriver`/`fromDriver` closures wired into `customType` (column.ts) are
  // otherwise only tested via the standalone codec functions, so the wiring
  // itself — including the SQL-NULL safety net — was never exercised.
  describe('codec wiring on the built column', () => {
    type Mapper = {
      mapToDriverValue(value: unknown): unknown
      mapFromDriverValue(value: unknown): unknown
    }
    const mapperFor = (name: string): Mapper => {
      const table = pgTable('users', {
        [name]: makeEqlV3Column(v3Types.TextEq(name)),
      } as never)
      return (table as unknown as Record<string, Mapper>)[name]
    }

    const ENVELOPE = {
      v: 3,
      i: { t: 'users', c: 'nickname' },
      c: 'mBbKciphertext',
      hm: 'hmac',
    }

    it('serialises an envelope on write and parses it back on read', () => {
      const column = mapperFor('nickname')
      const driverValue = column.mapToDriverValue(ENVELOPE)

      expect(driverValue).toBe(JSON.stringify(ENVELOPE))
      expect(column.mapFromDriverValue(driverValue)).toEqual(ENVELOPE)
    })

    it('maps a null envelope to SQL NULL on write', () => {
      expect(mapperFor('nickname').mapToDriverValue(null)).toBeNull()
    })

    it('rejects a non-envelope driver value rather than passing it through', () => {
      expect(() => mapperFor('nickname').mapFromDriverValue('5')).toThrow(
        /EQL encrypted envelope/,
      )
    })
  })
})
