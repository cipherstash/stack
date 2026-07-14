import type { ClientBase, QueryConfig, QueryResult, QueryResultRow } from 'pg'
import { describe, expect, it } from 'vitest'
import { detectColumnEqlVersion } from '../version.js'

interface RecordedQuery {
  text: string
  values: unknown[]
}

function createMockClient(rows: Array<Record<string, unknown>>): {
  client: ClientBase
  queries: RecordedQuery[]
} {
  const queries: RecordedQuery[] = []
  const client = {
    query(config: string | QueryConfig, values?: unknown[]) {
      const text = typeof config === 'string' ? config : config.text
      queries.push({ text, values: values ?? [] })
      return Promise.resolve({
        rows,
        rowCount: rows.length,
        command: '',
        oid: 0,
        fields: [],
      } as unknown as QueryResult<QueryResultRow>)
    },
  } as unknown as ClientBase
  return { client, queries }
}

describe('detectColumnEqlVersion', () => {
  it('maps the eql_v2_encrypted domain to v2', async () => {
    const { client } = createMockClient([{ domain_name: 'eql_v2_encrypted' }])
    expect(
      await detectColumnEqlVersion(client, 'users', 'email_encrypted'),
    ).toBe('v2')
  })

  it('maps any concrete eql_v3_* domain to v3', async () => {
    for (const domain of [
      'eql_v3_text_search',
      'eql_v3_text_match',
      'eql_v3_int8_ord',
      'eql_v3_encrypted',
    ]) {
      const { client } = createMockClient([{ domain_name: domain }])
      expect(
        await detectColumnEqlVersion(client, 'users', 'email_encrypted'),
      ).toBe('v3')
    }
  })

  it('returns null for a plaintext column (base type, not a domain)', async () => {
    const { client } = createMockClient([{ domain_name: 'text' }])
    expect(await detectColumnEqlVersion(client, 'users', 'email')).toBeNull()
  })

  it('returns null when the column/table is not found', async () => {
    const { client } = createMockClient([])
    expect(await detectColumnEqlVersion(client, 'nope', 'missing')).toBeNull()
  })

  it('passes the qualified table name and column as bind params (to_regclass)', async () => {
    const { client, queries } = createMockClient([
      { domain_name: 'eql_v3_text_search' },
    ])
    await detectColumnEqlVersion(client, 'app.users', 'email_encrypted')
    expect(queries).toHaveLength(1)
    expect(queries[0].text).toContain('to_regclass($1)')
    expect(queries[0].values).toEqual(['app.users', 'email_encrypted'])
  })
})
