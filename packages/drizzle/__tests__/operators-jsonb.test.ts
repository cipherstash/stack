import { encryptedType, ProtectOperatorError } from '@cipherstash/drizzle/pg'
import { pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it } from 'vitest'
import { setup } from './test-utils'

const docsTable = pgTable('json_docs', {
  metadata: encryptedType<Record<string, unknown>>('metadata', {
    dataType: 'json',
    searchableJson: true,
  }),
  noJsonConfig: encryptedType<string>('no_json_config', {
    equality: true,
  }),
})

describe('createProtectOperators JSONB selector typing', () => {
  it('casts jsonbPathQueryFirst selector params to eql_v2_encrypted', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.jsonbPathQueryFirst(
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
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.jsonbPathExists(
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
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.jsonbGet(
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
  it('throws ProtectOperatorError when column lacks searchableJson config', () => {
    const { protectOps } = setup()

    expect(() =>
      protectOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path'),
    ).toThrow(ProtectOperatorError)

    expect(() =>
      protectOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path'),
    ).toThrow(/searchableJson/)
  })

  it('throws ProtectOperatorError for jsonbPathExists without searchableJson', () => {
    const { protectOps } = setup()

    expect(() =>
      protectOps.jsonbPathExists(docsTable.noJsonConfig, '$.path'),
    ).toThrow(ProtectOperatorError)
  })

  it('throws ProtectOperatorError for jsonbGet without searchableJson', () => {
    const { protectOps } = setup()

    expect(() => protectOps.jsonbGet(docsTable.noJsonConfig, '$.path')).toThrow(
      ProtectOperatorError,
    )
  })

  it('error includes column name and operator context', () => {
    const { protectOps } = setup()

    try {
      protectOps.jsonbPathQueryFirst(docsTable.noJsonConfig, '$.path')
      expect.fail('Should have thrown')
    } catch (error) {
      expect(error).toBeInstanceOf(ProtectOperatorError)
      const opError = error as ProtectOperatorError
      expect(opError.context?.columnName).toBe('no_json_config')
      expect(opError.context?.operator).toBe('jsonbPathQueryFirst')
    }
  })
})

describe('JSONB batched operations', () => {
  it('batches jsonbPathQueryFirst and jsonbGet in protectOps.and()', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.and(
      protectOps.jsonbPathQueryFirst(docsTable.metadata, '$.profile.email'),
      protectOps.jsonbGet(docsTable.metadata, '$.profile.name'),
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

  it('batches jsonbPathExists and jsonbPathQueryFirst in protectOps.or()', async () => {
    const { encryptQuery, protectOps, dialect } = setup()

    const condition = await protectOps.or(
      protectOps.jsonbPathExists(docsTable.metadata, '$.profile.email'),
      protectOps.jsonbPathQueryFirst(docsTable.metadata, '$.profile.name'),
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
    const { protectOps, dialect } = setup()

    const condition = await protectOps.and(
      protectOps.jsonbPathQueryFirst(docsTable.metadata, '$.a'),
      protectOps.jsonbPathExists(docsTable.metadata, '$.b'),
    )
    const query = dialect.sqlToQuery(condition)

    // AND combines conditions
    expect(query.sql).toContain(' and ')
  })

  it('generates SQL combining conditions with OR', async () => {
    const { protectOps, dialect } = setup()

    const condition = await protectOps.or(
      protectOps.jsonbPathQueryFirst(docsTable.metadata, '$.a'),
      protectOps.jsonbPathExists(docsTable.metadata, '$.b'),
    )
    const query = dialect.sqlToQuery(condition)

    // OR combines conditions
    expect(query.sql).toContain(' or ')
  })
})
