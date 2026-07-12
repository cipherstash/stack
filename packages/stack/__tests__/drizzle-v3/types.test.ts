import { describe, expect, it } from 'vitest'
import { types as v3Types } from '@/eql/v3'
import { getEqlV3Column } from '@/eql/v3/drizzle/column'
import { types } from '@/eql/v3/drizzle/types'

describe('v3 drizzle types namespace', () => {
  it('exposes the same factory names as @/eql/v3 types', () => {
    expect(Object.keys(types).sort()).toEqual(Object.keys(v3Types).sort())
  })

  it.each(
    Object.entries(types),
  )('%s mirrors the authoring DSL and recovers the concrete eql type', (factoryName, factory) => {
    const drizzleColumn = factory(factoryName)
    const authoredColumn =
      v3Types[factoryName as keyof typeof v3Types](factoryName)

    expect(getEqlV3Column(factoryName, drizzleColumn)?.getEqlType()).toBe(
      authoredColumn.getEqlType(),
    )
  })
})
