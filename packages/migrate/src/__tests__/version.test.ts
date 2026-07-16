import type { ClientBase } from 'pg'
import { describe, expect, it, vi } from 'vitest'
import {
  classifyEqlDomain,
  detectColumnEqlVersion,
  listEncryptedColumns,
  resolveEncryptedColumn,
} from '../version.js'

function mockClient(rows: Array<Record<string, unknown>>) {
  const query = vi.fn().mockResolvedValue({ rows })
  return { client: { query } as unknown as ClientBase, query }
}

describe('classifyEqlDomain', () => {
  it('maps eql_v2_encrypted to 2', () => {
    expect(classifyEqlDomain('eql_v2_encrypted')).toBe(2)
  })

  it('maps any eql_v3_* domain to 3', () => {
    for (const domain of [
      'eql_v3_text_search',
      'eql_v3_text_match',
      'eql_v3_int8_ord',
      'eql_v3_encrypted',
    ]) {
      expect(classifyEqlDomain(domain)).toBe(3)
    }
  })

  it('maps non-EQL types to null', () => {
    expect(classifyEqlDomain('text')).toBeNull()
    expect(classifyEqlDomain('jsonb')).toBeNull()
    expect(classifyEqlDomain('citext')).toBeNull()
    // Prefix is `eql_v3_` with the underscore — a hypothetical future
    // `eql_v30_*` generation must not classify as v3.
    expect(classifyEqlDomain('eql_v30_text')).toBeNull()
    expect(classifyEqlDomain('eql_v3')).toBeNull()
  })
})

describe('detectColumnEqlVersion', () => {
  it('classifies from the domain type', async () => {
    const { client } = mockClient([{ domain_name: 'eql_v2_encrypted' }])
    expect(
      await detectColumnEqlVersion(client, 'users', 'email_encrypted'),
    ).toBe(2)
  })

  it('returns null for a plaintext column (base type, not a domain)', async () => {
    const { client } = mockClient([{ domain_name: 'text' }])
    expect(await detectColumnEqlVersion(client, 'users', 'email')).toBeNull()
  })

  it('returns null when the column/table is not found', async () => {
    const { client } = mockClient([])
    expect(await detectColumnEqlVersion(client, 'nope', 'missing')).toBeNull()
  })

  it('resolves the table case-exactly: quoted-identifier semantics, not raw to_regclass parsing', async () => {
    // A bare to_regclass($1) case-folds 'User' to 'user', silently missing
    // Prisma-style quoted tables while the rest of the pipeline (which
    // quotes identifiers verbatim) works — wedging a v3 column into the v2
    // lifecycle. The format('%I', …) wrapping is what prevents that.
    const { client, query } = mockClient([
      { domain_name: 'eql_v3_text_search' },
    ])
    await detectColumnEqlVersion(client, 'User', 'email_encrypted')
    const [sql, values] = query.mock.calls[0] as [string, unknown[]]
    expect(sql).toContain("format('%I'")
    expect(sql).not.toMatch(/to_regclass\(\$1\)/)
    expect(values).toEqual(['User', null, 'email_encrypted'])
  })

  it('splits schema-qualified names on the first dot, like qualifyTable', async () => {
    const { client, query } = mockClient([
      { domain_name: 'eql_v3_text_search' },
    ])
    await detectColumnEqlVersion(client, 'app.Users', 'email_encrypted')
    const [, values] = query.mock.calls[0] as [string, unknown[]]
    expect(values).toEqual(['Users', 'app', 'email_encrypted'])
  })
})

describe('listEncryptedColumns', () => {
  it('returns only EQL-domain columns, classified', async () => {
    const { client } = mockClient([
      { column: 'id', domain_name: 'int8' },
      { column: 'email', domain_name: 'text' },
      { column: 'email_enc', domain_name: 'eql_v3_text_search' },
      { column: 'ssn_encrypted', domain_name: 'eql_v2_encrypted' },
    ])
    expect(await listEncryptedColumns(client, 'users')).toEqual([
      { column: 'email_enc', domain: 'eql_v3_text_search', version: 3 },
      { column: 'ssn_encrypted', domain: 'eql_v2_encrypted', version: 2 },
    ])
  })
})

describe('resolveEncryptedColumn', () => {
  const TABLE = [
    { column: 'id', domain_name: 'int8' },
    { column: 'email', domain_name: 'text' },
  ]

  it('an explicit hint wins, validated against the domain type', async () => {
    const { client } = mockClient([
      ...TABLE,
      { column: 'email_enc', domain_name: 'eql_v3_text_search' },
      { column: 'email_encrypted', domain_name: 'eql_v3_text_eq' },
    ])
    expect(
      await resolveEncryptedColumn(client, 'users', 'email', 'email_enc'),
    ).toEqual({ column: 'email_enc', domain: 'eql_v3_text_search', version: 3 })
  })

  it('a hint naming a non-EQL column resolves to null, not a guess', async () => {
    const { client } = mockClient([
      ...TABLE,
      { column: 'email_encrypted', domain_name: 'eql_v3_text_eq' },
    ])
    expect(
      await resolveEncryptedColumn(client, 'users', 'email', 'email'),
    ).toBeNull()
  })

  it('falls back to the <column>_encrypted convention', async () => {
    const { client } = mockClient([
      ...TABLE,
      { column: 'email_encrypted', domain_name: 'eql_v3_text_eq' },
      { column: 'other_encrypted', domain_name: 'eql_v3_text_eq' },
    ])
    expect(await resolveEncryptedColumn(client, 'users', 'email')).toEqual({
      column: 'email_encrypted',
      domain: 'eql_v3_text_eq',
      version: 3,
    })
  })

  it('resolves a sole EQL column regardless of its name — the convention is never required', async () => {
    const { client } = mockClient([
      ...TABLE,
      { column: 'secret_blob', domain_name: 'eql_v3_text_search' },
    ])
    expect(await resolveEncryptedColumn(client, 'users', 'email')).toEqual({
      column: 'secret_blob',
      domain: 'eql_v3_text_search',
      version: 3,
    })
  })

  it('returns null when several EQL columns exist and none is identifiable', async () => {
    const { client } = mockClient([
      ...TABLE,
      { column: 'a_enc', domain_name: 'eql_v3_text_eq' },
      { column: 'b_enc', domain_name: 'eql_v3_text_eq' },
    ])
    expect(await resolveEncryptedColumn(client, 'users', 'email')).toBeNull()
  })

  it('returns null on a table with no EQL columns', async () => {
    const { client } = mockClient(TABLE)
    expect(await resolveEncryptedColumn(client, 'users', 'email')).toBeNull()
  })
})
