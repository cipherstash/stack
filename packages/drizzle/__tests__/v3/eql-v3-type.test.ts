import { pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { getEncryptedColumnConfig } from '../../src/pg/index'
import { eqlV3Type } from '../../src/pg/v3/eql-v3-type'

describe('eqlV3Type', () => {
  it('dataType() returns the capability domain for each index', () => {
    const storage = eqlV3Type<string>('t_storage', { dataType: 'text' })
    const eqCol = eqlV3Type<string>('t_eq', {
      dataType: 'text',
      index: 'equality',
    })
    const matchCol = eqlV3Type<string>('t_match', {
      dataType: 'text',
      index: 'freeTextSearch',
    })
    const ordCol = eqlV3Type<string>('t_ord', {
      dataType: 'text',
      index: 'orderAndRange',
    })

    // The customType dataType() callback lives at config.customTypeParams on the
    // raw Drizzle column builder (before pgTable); getSQLType() exposes the same
    // value post-pgTable. Reading the internal path keeps the four-builder shape.
    // biome-ignore lint/suspicious/noExplicitAny: reading Drizzle internals in test
    expect((storage as any).config.customTypeParams.dataType()).toBe(
      'eql_v3.text',
    )
    // biome-ignore lint/suspicious/noExplicitAny: reading Drizzle internals in test
    expect((eqCol as any).config.customTypeParams.dataType()).toBe(
      'eql_v3.text_eq',
    )
    // biome-ignore lint/suspicious/noExplicitAny: reading Drizzle internals in test
    expect((matchCol as any).config.customTypeParams.dataType()).toBe(
      'eql_v3.text_match',
    )
    // biome-ignore lint/suspicious/noExplicitAny: reading Drizzle internals in test
    expect((ordCol as any).config.customTypeParams.dataType()).toBe(
      'eql_v3.text_ord',
    )
  })

  it('registers an EncryptedColumnConfig discoverable by extraction', () => {
    const table = pgTable('v3_users', {
      t_eq: eqlV3Type<string>('t_eq', { dataType: 'text', index: 'equality' }),
    })
    const config = getEncryptedColumnConfig('t_eq', table.t_eq)
    expect(config).toBeDefined()
    // text → equality index flag set; internal CastAs is 'string'
    expect(config?.equality).toBe(true)
    expect(config?.dataType).toBe('string')
  })

  it('maps freeTextSearch index to the freeTextSearch config flag', () => {
    const table = pgTable('v3_b', {
      t_match: eqlV3Type<string>('t_match', {
        dataType: 'text',
        index: 'freeTextSearch',
      }),
    })
    expect(
      getEncryptedColumnConfig('t_match', table.t_match)?.freeTextSearch,
    ).toBe(true)
  })

  it('maps orderAndRange index to the orderAndRange config flag', () => {
    const table = pgTable('v3_c', {
      t_ord: eqlV3Type<string>('t_ord', {
        dataType: 'text',
        index: 'orderAndRange',
      }),
    })
    expect(getEncryptedColumnConfig('t_ord', table.t_ord)?.orderAndRange).toBe(
      true,
    )
  })
})
