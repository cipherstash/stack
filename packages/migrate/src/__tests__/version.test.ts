import type { ClientBase } from 'pg'
import { describe, expect, it, vi } from 'vitest'
import {
  classifyEqlDomain,
  detectColumnEqlVersion,
  type EncryptedColumnInfo,
  listEncryptedColumns,
  pickEncryptedColumn,
  resolveEncryptedColumn,
} from '../version.js'

// The one contained type-erasing cast in this file: the functions under
// test take a pg.ClientBase but only ever call `.query`, and ClientBase's
// overloaded query signature can't be satisfied by a structural fixture.
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

describe('pickEncryptedColumn', () => {
  const col = (
    column: string,
    domain = 'eql_v3_text_eq',
    version: 2 | 3 = 3,
  ): EncryptedColumnInfo => ({ column, domain, version })

  it('an explicit hint wins, validated against the domain type', () => {
    const candidates = [
      col('email_enc', 'eql_v3_text_search'),
      col('email_encrypted'),
    ]
    expect(pickEncryptedColumn(candidates, 'email', 'email_enc')).toEqual({
      column: 'email_enc',
      domain: 'eql_v3_text_search',
      version: 3,
      via: 'hint',
    })
  })

  it('a hint naming a non-EQL column resolves to null, not a guess', () => {
    expect(
      pickEncryptedColumn([col('email_encrypted')], 'email', 'email'),
    ).toBeNull()
  })

  it('falls back to the <column>_encrypted convention', () => {
    const candidates = [col('email_encrypted'), col('other_encrypted')]
    expect(pickEncryptedColumn(candidates, 'email')).toEqual({
      column: 'email_encrypted',
      domain: 'eql_v3_text_eq',
      version: 3,
      via: 'convention',
    })
  })

  it("resolves a sole EQL column regardless of its name — flagged 'sole', because uniqueness cannot prove the pairing", () => {
    // The convention is never REQUIRED (the whole point of self-describing
    // v3 types), but a by-elimination match may encrypt a different field —
    // `via: 'sole'` is what lets destructive callers refuse to act on it.
    expect(
      pickEncryptedColumn([col('secret_blob', 'eql_v3_text_search')], 'email'),
    ).toEqual({
      column: 'secret_blob',
      domain: 'eql_v3_text_search',
      version: 3,
      via: 'sole',
    })
  })

  it('never resolves the plaintext column to itself', () => {
    // Post-cutover v2: `email` itself carries the v2 domain. It is the
    // ciphertext, not a counterpart of itself.
    expect(
      pickEncryptedColumn([col('email', 'eql_v2_encrypted', 2)], 'email'),
    ).toBeNull()
  })

  it('returns null when several EQL columns exist and none is identifiable', () => {
    expect(
      pickEncryptedColumn([col('a_enc'), col('b_enc')], 'email'),
    ).toBeNull()
  })

  it('returns null with no EQL columns', () => {
    expect(pickEncryptedColumn([], 'email')).toBeNull()
  })
})

describe('resolveEncryptedColumn', () => {
  it('picks from the live catalog (fetch + pick passthrough)', async () => {
    const { client } = mockClient([
      { column: 'id', domain_name: 'int8' },
      { column: 'email', domain_name: 'text' },
      { column: 'email_encrypted', domain_name: 'eql_v3_text_eq' },
    ])
    expect(await resolveEncryptedColumn(client, 'users', 'email')).toEqual({
      column: 'email_encrypted',
      domain: 'eql_v3_text_eq',
      version: 3,
      via: 'convention',
    })
  })
})
