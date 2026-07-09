import fc from 'fast-check'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { groupIntrospectionRows } from '@/supabase/introspect'

describe('groupIntrospectionRows', () => {
  it('groups rows by table, preserving row order as column order', () => {
    const result = groupIntrospectionRows([
      { table_name: 'users', column_name: 'id', domain_name: null },
      { table_name: 'users', column_name: 'email', domain_name: 'text_search' },
      { table_name: 'users', column_name: 'note', domain_name: null },
      { table_name: 'orders', column_name: 'id', domain_name: null },
      {
        table_name: 'orders',
        column_name: 'total',
        domain_name: 'integer_ord',
      },
    ])

    expect(result).toEqual([
      {
        tableName: 'users',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'email', domainName: 'text_search' },
          { columnName: 'note', domainName: null },
        ],
      },
      {
        tableName: 'orders',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'total', domainName: 'integer_ord' },
        ],
      },
    ])
  })

  it('returns an empty array for no rows', () => {
    expect(groupIntrospectionRows([])).toEqual([])
  })

  it('PROPERTY: preserves total column count, first-seen table order, and domains', () => {
    const rowArb = fc.record({
      table_name: fc.constantFrom('a', 'b', 'c'),
      column_name: fc.string(),
      domain_name: fc.option(fc.string(), { nil: null }),
    })
    fc.assert(
      fc.property(fc.array(rowArb), (rows) => {
        const grouped = groupIntrospectionRows(rows)
        // (1) Column count is preserved.
        const total = grouped.reduce((n, t) => n + t.columns.length, 0)
        expect(total).toBe(rows.length)
        // (2) Table order is first-seen order of the input.
        const firstSeen: string[] = []
        for (const r of rows) {
          if (!firstSeen.includes(r.table_name)) firstSeen.push(r.table_name)
        }
        expect(grouped.map((t) => t.tableName)).toEqual(firstSeen)
        // (3) Per-table column names+domains match the input rows in order.
        for (const t of grouped) {
          const expected = rows
            .filter((r) => r.table_name === t.tableName)
            .map((r) => ({
              columnName: r.column_name,
              domainName: r.domain_name,
            }))
          expect(t.columns).toEqual(expected)
        }
      }),
    )
  })
})

describe('introspect connection error handling', () => {
  afterEach(() => vi.resetModules())

  it('surfaces the connect error, not a failing end()', async () => {
    vi.doMock('pg', () => {
      class Client {
        connect() {
          return Promise.reject(new Error('ECONNREFUSED'))
        }
        end() {
          // A throwing end() must NOT replace the connect error.
          return Promise.reject(new Error('end failed'))
        }
        query() {
          return Promise.resolve({ rows: [] })
        }
      }
      return { default: { Client } }
    })

    const { introspect } = await import('@/supabase/introspect')
    await expect(introspect('postgres://unreachable')).rejects.toThrow(
      'ECONNREFUSED',
    )
    vi.doUnmock('pg')
  })
})
