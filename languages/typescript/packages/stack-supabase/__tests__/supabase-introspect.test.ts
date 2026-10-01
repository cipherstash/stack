import fc from 'fast-check'
import { afterEach, describe, expect, it, vi } from 'vitest'
import {
  eqlRequiresQueryDomains,
  groupIntrospectionRows,
  loadPg,
} from '../src/introspect'

describe('eqlRequiresQueryDomains', () => {
  it.each([
    [null, true],
    ['unknown', true],
    ['3.0.0', false],
    ['3.0.1', false],
    ['3.0.2', true],
    ['3.1.0', true],
    ['4.0.0', true],
  ] as const)('classifies %s', (version, expected) => {
    expect(eqlRequiresQueryDomains(version)).toBe(expected)
  })
})

describe('groupIntrospectionRows', () => {
  it('groups rows by table, preserving row order as column order', () => {
    const result = groupIntrospectionRows([
      { table_name: 'users', column_name: 'id', domain_name: null },
      {
        table_name: 'users',
        column_name: 'email',
        domain_name: 'eql_v3_text_search',
      },
      { table_name: 'users', column_name: 'note', domain_name: null },
      { table_name: 'orders', column_name: 'id', domain_name: null },
      {
        table_name: 'orders',
        column_name: 'total',
        domain_name: 'eql_v3_integer_ord',
      },
    ])

    expect(result).toEqual([
      {
        tableName: 'users',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'email', domainName: 'eql_v3_text_search' },
          { columnName: 'note', domainName: null },
        ],
      },
      {
        tableName: 'orders',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'total', domainName: 'eql_v3_integer_ord' },
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

describe('introspect happy path', () => {
  afterEach(() => vi.resetModules())

  it('issues all queries, builds the domains, and closes the connection', async () => {
    const end = vi.fn(() => Promise.resolve())
    const queries: Array<{ sql: string; params?: unknown[] }> = []

    vi.doMock('pg', () => {
      class Client {
        connect() {
          return Promise.resolve()
        }
        end = end
        query(sql: string, params?: unknown[]) {
          queries.push({ sql, params })
          // The unmodelled query is the parameterised one.
          if (sql.includes('to_regnamespace')) {
            return Promise.resolve({ rows: [{ version: '3.0.2' }] })
          }
          return Promise.resolve({
            rows: params
              ? [
                  {
                    table_name: 'users',
                    column_name: 'legacy',
                    domain_name: 'unsupported_domain',
                  },
                ]
              : [
                  { table_name: 'users', column_name: 'id', domain_name: null },
                  {
                    table_name: 'users',
                    column_name: 'email',
                    domain_name: 'eql_v3_text_search',
                  },
                ],
          })
        }
      }
      return { default: { Client } }
    })

    const { introspect } = await import('../src/introspect')
    const { tables, unmodelled, eqlVersion } = await introspect('postgres://ok')

    expect(queries).toHaveLength(3)
    // The registry IS the query parameter — it must be pushed into Postgres,
    // not re-derived client-side.
    const parameterised = queries.find((q) => q.params)!
    expect(parameterised.params?.[0]).toContain('eql_v3_text_search')

    expect(tables).toEqual([
      {
        tableName: 'users',
        columns: [
          { columnName: 'id', domainName: null },
          { columnName: 'email', domainName: 'eql_v3_text_search' },
        ],
      },
    ])
    expect(unmodelled.get('users')).toEqual([
      { columnName: 'legacy', domainName: 'unsupported_domain' },
    ])
    expect(eqlVersion).toBe('3.0.2')
    // A leaked connection is invisible to every other assertion here.
    expect(end).toHaveBeenCalledTimes(1)

    vi.doUnmock('pg')
  })

  it('closes the connection when a query throws', async () => {
    const end = vi.fn(() => Promise.resolve())

    vi.doMock('pg', () => {
      class Client {
        connect() {
          return Promise.resolve()
        }
        end = end
        query() {
          return Promise.reject(new Error('relation does not exist'))
        }
      }
      return { default: { Client } }
    })

    const { introspect } = await import('../src/introspect')
    await expect(introspect('postgres://ok')).rejects.toThrow(
      'relation does not exist',
    )
    expect(end).toHaveBeenCalledTimes(1)

    vi.doUnmock('pg')
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

    const { introspect } = await import('../src/introspect')
    await expect(introspect('postgres://unreachable')).rejects.toThrow(
      'ECONNREFUSED',
    )
    vi.doUnmock('pg')
  })
})

describe('loadPg', () => {
  const failingImport = (err: unknown) => () => Promise.reject(err)

  for (const code of ['ERR_MODULE_NOT_FOUND', 'MODULE_NOT_FOUND']) {
    it(`remaps a missing optional \`pg\` peer (${code}) to an install message`, async () => {
      const err = Object.assign(new Error("Cannot find package 'pg'"), { code })

      await expect(loadPg(failingImport(err))).rejects.toThrow(
        /'pg' is not installed/,
      )
      await expect(loadPg(failingImport(err))).rejects.toHaveProperty(
        'cause',
        err,
      )
    })
  }

  it('does not swallow an unrelated module-load failure', async () => {
    const err = new Error('boom: pg self-check failed')
    await expect(loadPg(failingImport(err))).rejects.toBe(err)
  })
})
