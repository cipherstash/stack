import type {
  ClientBase,
  QueryArrayConfig,
  QueryArrayResult,
  QueryConfig,
  QueryResult,
  QueryResultRow,
  Submittable,
} from 'pg'
import { describe, expect, it } from 'vitest'
import { appendEvent, latestByColumn, progress } from '../state.js'

interface RecordedQuery {
  text: string
  values: unknown[]
}

function createMockClient(
  responses: Array<{ rows: Array<Record<string, unknown>> }>,
): { client: ClientBase; queries: RecordedQuery[] } {
  const queries: RecordedQuery[] = []
  let i = 0
  const client = {
    query(
      config: string | QueryConfig | QueryArrayConfig | Submittable,
      values?: unknown[],
    ) {
      const text =
        typeof config === 'string' ? config : (config as QueryConfig).text
      queries.push({ text, values: values ?? [] })
      const resp = responses[i++] ?? { rows: [] }
      return Promise.resolve({
        rows: resp.rows,
        rowCount: resp.rows.length,
        command: '',
        oid: 0,
        fields: [],
      } as unknown as QueryResult<QueryResultRow> | QueryArrayResult<unknown[]>)
    },
  } as unknown as ClientBase
  return { client, queries }
}

describe('appendEvent', () => {
  it('inserts into cipherstash.cs_migrations with all fields', async () => {
    const { client, queries } = createMockClient([
      {
        rows: [
          {
            id: 42,
            table_name: 'users',
            column_name: 'email',
            event: 'backfill_checkpoint',
            phase: 'backfilling',
            cursor_value: '1234',
            rows_processed: 500,
            rows_total: 1000,
            details: { chunkIndex: 2 },
            created_at: new Date('2026-04-23T00:00:00Z'),
          },
        ],
      },
    ])

    const row = await appendEvent(client, {
      tableName: 'users',
      columnName: 'email',
      event: 'backfill_checkpoint',
      phase: 'backfilling',
      cursorValue: '1234',
      rowsProcessed: 500,
      rowsTotal: 1000,
      details: { chunkIndex: 2 },
    })

    expect(queries).toHaveLength(1)
    expect(queries[0]?.text).toMatch(/INSERT INTO cipherstash\.cs_migrations/)
    expect(queries[0]?.values).toEqual([
      'users',
      'email',
      'backfill_checkpoint',
      'backfilling',
      '1234',
      500,
      1000,
      { chunkIndex: 2 },
    ])
    expect(row.id).toBe('42')
    expect(row.rowsProcessed).toBe(500)
  })

  it('nulls optional fields when omitted', async () => {
    const { client, queries } = createMockClient([
      {
        rows: [
          {
            id: 1,
            table_name: 'users',
            column_name: 'email',
            event: 'schema_added',
            phase: 'schema-added',
            cursor_value: null,
            rows_processed: null,
            rows_total: null,
            details: null,
            created_at: new Date(),
          },
        ],
      },
    ])

    await appendEvent(client, {
      tableName: 'users',
      columnName: 'email',
      event: 'schema_added',
      phase: 'schema-added',
    })

    expect(queries[0]?.values.slice(4)).toEqual([null, null, null, null])
  })
})

describe('latestByColumn', () => {
  it('returns a map keyed by `table.column`', async () => {
    const { client } = createMockClient([
      {
        rows: [
          {
            id: 10,
            table_name: 'users',
            column_name: 'email',
            event: 'backfilled',
            phase: 'backfilled',
            cursor_value: null,
            rows_processed: 100,
            rows_total: 100,
            details: null,
            created_at: new Date(),
          },
          {
            id: 9,
            table_name: 'orders',
            column_name: 'notes',
            event: 'dual_writing',
            phase: 'dual-writing',
            cursor_value: null,
            rows_processed: null,
            rows_total: null,
            details: null,
            created_at: new Date(),
          },
        ],
      },
    ])

    const map = await latestByColumn(client)
    expect(map.size).toBe(2)
    expect(map.get('users.email')?.phase).toBe('backfilled')
    expect(map.get('orders.notes')?.phase).toBe('dual-writing')
  })
})

describe('progress', () => {
  it('returns null when no rows exist', async () => {
    const { client } = createMockClient([{ rows: [] }])
    const result = await progress(client, 'users', 'email')
    expect(result).toBeNull()
  })

  it('returns the latest row', async () => {
    const { client } = createMockClient([
      {
        rows: [
          {
            id: 5,
            table_name: 'users',
            column_name: 'email',
            event: 'backfill_checkpoint',
            phase: 'backfilling',
            cursor_value: '999',
            rows_processed: 3000,
            rows_total: 10000,
            details: null,
            created_at: new Date(),
          },
        ],
      },
    ])
    const result = await progress(client, 'users', 'email')
    expect(result?.cursorValue).toBe('999')
    expect(result?.rowsProcessed).toBe(3000)
  })
})
