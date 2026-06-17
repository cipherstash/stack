import { PgDialect, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it, vi } from 'vitest'
import {
  createEncryptionOperators,
  EncryptionOperatorError,
  encryptedType,
} from '@/drizzle'
import type { EncryptionClient } from '@/encryption'

const ENCRYPTED_VALUE = '{"v":"encrypted-value"}'

function createMockEncryptionClient() {
  const encryptQuery = vi.fn(async (termsOrValue: unknown) => {
    if (Array.isArray(termsOrValue)) {
      return { data: termsOrValue.map(() => ENCRYPTED_VALUE) }
    }
    return { data: ENCRYPTED_VALUE }
  })

  return {
    client: { encryptQuery } as unknown as EncryptionClient,
    encryptQuery,
  }
}

function setup() {
  const { client, encryptQuery } = createMockEncryptionClient()
  const encryptionOps = createEncryptionOperators(client)
  const dialect = new PgDialect()
  return { client, encryptQuery, encryptionOps, dialect }
}

const docsTable = pgTable('json_docs', {
  metadata: encryptedType<Record<string, unknown>>('metadata', {
    dataType: 'json',
    searchableJson: true,
  }),
  noJsonConfig: encryptedType<string>('no_json_config', {
    equality: true,
  }),
})

describe('createEncryptionOperators JSONB selector typing', () => {
  it('casts jsonbPathQueryFirst selector params to eql_v2_encrypted', async () => {
    const { encryptQuery, encryptionOps, dialect } = setup()

    const condition = await encryptionOps.jsonbPathQueryFirst(
      docsTable.metadata,
      '$.profile.email',
    )
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toMatch(
      /eql_v2\.jsonb_path_query_first\([^,]+,\s*\$\d+::eql_v2_encrypted\)/,
    )
    expect(query.params).toHaveLength(1)
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'steVecSelector' },
    ])
  })

  it('casts jsonbPathExists selector params to eql_v2_encrypted', async () => {
    const { encryptQuery, encryptionOps, dialect } = setup()

    const condition = await encryptionOps.jsonbPathExists(
      docsTable.metadata,
      '$.profile.email',
    )
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toMatch(
      /eql_v2\.jsonb_path_exists\([^,]+,\s*\$\d+::eql_v2_encrypted\)/,
    )
    expect(query.params).toHaveLength(1)
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'steVecSelector' },
    ])
  })

  it('casts jsonbGet selector params to eql_v2_encrypted', async () => {
    const { encryptQuery, encryptionOps, dialect } = setup()

    const condition = await encryptionOps.jsonbGet(
      docsTable.metadata,
      '$.profile.email',
    )
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toMatch(/->\s*\$\d+::eql_v2_encrypted/)
    expect(query.params).toHaveLength(1)
    expect(query.params[0]).toContain('encrypted-value')
    expect(encryptQuery).toHaveBeenCalledTimes(1)
    expect(encryptQuery.mock.calls[0]?.[0]).toMatchObject([
      { queryType: 'steVecSelector' },
    ])
  })
})

describe('JSONB operator error paths', () => {
  it('throws EncryptionOperatorError when column lacks searchableJson config', () => {
    const { encryptionOps } = setup()

    expect(() =>
      encryptionOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path'),
    ).toThrow(EncryptionOperatorError)

    expect(() =>
      encryptionOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path'),
    ).toThrow(/searchableJson/)
  })

  it('throws EncryptionOperatorError for jsonbPathExists without searchableJson', () => {
    const { encryptionOps } = setup()

    expect(() =>
      encryptionOps.jsonbPathExists(docsTable.noJsonConfig, '$.path'),
    ).toThrow(EncryptionOperatorError)
  })

  it('throws EncryptionOperatorError for jsonbGet without searchableJson', () => {
    const { encryptionOps } = setup()

    expect(() =>
      encryptionOps.jsonbGet(docsTable.noJsonConfig, '$.path'),
    ).toThrow(EncryptionOperatorError)
  })

  it('error includes column name and operator context', () => {
    const { encryptionOps } = setup()

    try {
      encryptionOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path')
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(EncryptionOperatorError)
      const opError = error as EncryptionOperatorError
      expect(opError.context?.columnName).toBe('no_json_config')
      expect(opError.context?.operator).toBe('jsonbPathQueryFirst')
    }
  })
})

describe('JSONB batched operations', () => {
  it('batches jsonbPathQueryFirst and jsonbGet in encryptionOps.and()', async () => {
    const { encryptQuery, encryptionOps, dialect } = setup()

    const condition = await encryptionOps.and(
      encryptionOps.jsonbPathQueryFirst(docsTable.metadata, '$.profile.email'),
      encryptionOps.jsonbGet(docsTable.metadata, '$.profile.name'),
    )
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.jsonb_path_query_first')
    expect(query.sql).toContain('->')
    // Verify batch encryption happened (at least one call with 2 terms)
    expect(
      encryptQuery.mock.calls.some(
        (call: unknown[]) => Array.isArray(call[0]) && call[0].length === 2,
      ),
    ).toBe(true)
  })

  it('batches jsonbPathExists and jsonbPathQueryFirst in encryptionOps.or()', async () => {
    const { encryptQuery, encryptionOps, dialect } = setup()

    const condition = await encryptionOps.or(
      encryptionOps.jsonbPathExists(docsTable.metadata, '$.profile.email'),
      encryptionOps.jsonbPathQueryFirst(docsTable.metadata, '$.profile.name'),
    )
    const query = dialect.sqlToQuery(condition)

    expect(query.sql).toContain('eql_v2.jsonb_path_exists')
    expect(query.sql).toContain('eql_v2.jsonb_path_query_first')
    // Verify batch encryption happened (at least one call with 2 terms)
    expect(
      encryptQuery.mock.calls.some(
        (call: unknown[]) => Array.isArray(call[0]) && call[0].length === 2,
      ),
    ).toBe(true)
  })

  it('generates SQL combining conditions with AND', async () => {
    const { encryptionOps, dialect } = setup()

    const condition = await encryptionOps.and(
      encryptionOps.jsonbPathQueryFirst(docsTable.metadata, '$.a'),
      encryptionOps.jsonbPathExists(docsTable.metadata, '$.b'),
    )
    const query = dialect.sqlToQuery(condition)

    // AND combines conditions
    expect(query.sql).toContain(' and ')
  })

  it('generates SQL combining conditions with OR', async () => {
    const { encryptionOps, dialect } = setup()

    const condition = await encryptionOps.or(
      encryptionOps.jsonbPathQueryFirst(docsTable.metadata, '$.a'),
      encryptionOps.jsonbPathExists(docsTable.metadata, '$.b'),
    )
    const query = dialect.sqlToQuery(condition)

    // OR combines conditions
    expect(query.sql).toContain(' or ')
  })
})
