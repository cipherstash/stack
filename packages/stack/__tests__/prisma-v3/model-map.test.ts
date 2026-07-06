import { describe, expect, it } from 'vitest'
import { encryptedTable, types } from '@/eql/v3'
import {
  buildModelMap,
  buildTableMeta,
  reconstructRow,
} from '@/eql/v3/prisma/model-map'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  createdOn: types.TimestampOrd('created_on'),
  dob: types.DateEq('dob'),
  age: types.IntegerOrd('age'),
})

const orders = encryptedTable('orders', {
  reference: types.TextEq('reference'),
})

describe('buildTableMeta', () => {
  const meta = buildTableMeta(users, 'User')

  it('records the model name and table', () => {
    expect(meta.modelName).toBe('User')
    expect(meta.table).toBe(users)
  })

  it('maps property names to db column names', () => {
    expect(meta.propToDb).toEqual({
      email: 'email',
      createdOn: 'created_on',
      dob: 'dob',
      age: 'age',
    })
  })

  it('collects encrypted property names', () => {
    expect([...meta.encryptedProps].sort()).toEqual([
      'age',
      'createdOn',
      'dob',
      'email',
    ])
  })

  it('collects date keys under BOTH property and db names', () => {
    // Raw SQL rows are keyed by db name, extension rows by property name —
    // Date reconstruction must cover both.
    expect([...meta.dateKeys].sort()).toEqual([
      'createdOn',
      'created_on',
      'dob',
    ])
  })
})

describe('reconstructRow', () => {
  const meta = buildTableMeta(users, 'User')

  it('rebuilds Date values from strings on property keys', () => {
    const row = reconstructRow(meta, {
      email: 'a@b.com',
      createdOn: '2026-01-02T03:04:05.000Z',
      age: 42,
    })
    expect(row.createdOn).toBeInstanceOf(Date)
    expect((row.createdOn as Date).toISOString()).toBe(
      '2026-01-02T03:04:05.000Z',
    )
    expect(row.email).toBe('a@b.com')
    expect(row.age).toBe(42)
  })

  it('rebuilds Date values on db-name keys (raw SQL rows)', () => {
    const row = reconstructRow(meta, {
      created_on: '2026-01-02T03:04:05.000Z',
    })
    expect(row.created_on).toBeInstanceOf(Date)
  })

  it('leaves null, undefined, and existing Date values alone', () => {
    const d = new Date('2026-01-01T00:00:00.000Z')
    const row = reconstructRow(meta, {
      createdOn: null,
      dob: d,
    })
    expect(row.createdOn).toBeNull()
    expect(row.dob).toBe(d)
  })

  it('does not mutate the input row', () => {
    const input = { createdOn: '2026-01-02T03:04:05.000Z' }
    reconstructRow(meta, input)
    expect(input.createdOn).toBe('2026-01-02T03:04:05.000Z')
  })
})

describe('buildModelMap', () => {
  it('keys metas by Prisma model name', () => {
    const { byModel } = buildModelMap({ User: users, Order: orders })
    expect(byModel.get('User')?.table).toBe(users)
    expect(byModel.get('Order')?.table).toBe(orders)
    expect(byModel.get('Nope')).toBeUndefined()
  })

  it('maps every column builder back to its table context', () => {
    const { byColumn } = buildModelMap({ User: users, Order: orders })
    const ctx = byColumn.get(users.age)
    expect(ctx?.tableName).toBe('users')
    expect(ctx?.dbName).toBe('age')
    expect(ctx?.table).toBe(users)
    expect(byColumn.get(orders.reference)?.tableName).toBe('orders')
  })

  it('exposes the built index set for gating', () => {
    const { byColumn } = buildModelMap({ User: users })
    expect(byColumn.get(users.email)?.indexes.unique).toBeTruthy()
    expect(byColumn.get(users.email)?.indexes.ore).toBeFalsy()
    expect(byColumn.get(users.age)?.indexes.ore).toBeTruthy()
  })

  it('rejects the same table registered under two models', () => {
    // One builder instance in two metas would make column→table resolution
    // ambiguous for the where builders.
    expect(() => buildModelMap({ User: users, Person: users })).toThrow(
      /registered under more than one model/i,
    )
  })
})
