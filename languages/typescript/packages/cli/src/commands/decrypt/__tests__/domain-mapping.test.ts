/**
 * The reverse type mapping and the uninstall embedding, checked against the
 * REAL `@cipherstash/eql` bundle this CLI ships with — not a hand-copied
 * list. A domain added to EQL without a plaintext mapping fails here, before a
 * user's `stash decrypt plan` meets it.
 */

import { readInstallSql, readUninstallSql } from '@cipherstash/eql/sql'
import { plaintextTypeForEqlDomain } from '@cipherstash/migrate'
import { describe, expect, it, vi } from 'vitest'

vi.mock('@/commands/encrypt/context.js', () => ({
  loadEncryptionContext: vi.fn(),
  requireTable: vi.fn(),
}))

import { splitUninstallSql } from '../drop.js'
import { drizzleColumnLine, drizzleImports } from '../lib/orm-hints.js'

/**
 * Every COLUMN domain the bundle creates: `public.eql_v3_*`. (`eql_v3.query_*`
 * needles and `eql_v3_internal.*` term types are never a column's type.)
 */
const columnDomains = [
  ...readInstallSql().matchAll(/CREATE DOMAIN public\.(eql_v3_[a-z0-9_]+)/g),
]
  .map((match) => match[1] as string)
  .filter((domain, index, all) => all.indexOf(domain) === index)

// SteVec fragment: the type of ONE element inside a searchable JSON
// document's `sv` array, not of a column. The catalog says so; mapping it to a
// plaintext type would invent one.
const NOT_A_COLUMN_TYPE = new Set(['eql_v3_json_entry'])

describe('reverse type mapping vs the shipped EQL bundle', () => {
  it('found the bundle’s column domains', () => {
    expect(columnDomains.length).toBeGreaterThan(40)
    expect(columnDomains).toContain('eql_v3_text_search')
    expect(columnDomains).toContain('eql_v3_json_search')
  })

  it.each(columnDomains.filter((domain) => !NOT_A_COLUMN_TYPE.has(domain)))(
    '%s maps back to a plaintext type',
    (domain) => {
      expect(plaintextTypeForEqlDomain(domain)).not.toBeNull()
    },
  )

  it('refuses the SteVec fragment domain', () => {
    for (const domain of NOT_A_COLUMN_TYPE) {
      expect(columnDomains).toContain(domain)
      expect(plaintextTypeForEqlDomain(domain)).toBeNull()
    }
  })
})

describe('splitUninstallSql', () => {
  it('splits the shipped uninstall script into its DROP SCHEMA statements', () => {
    expect(splitUninstallSql(readUninstallSql())).toEqual([
      'DROP SCHEMA IF EXISTS eql_v3 CASCADE',
      'DROP SCHEMA IF EXISTS eql_v3_internal CASCADE',
    ])
  })

  it('refuses a script it cannot split safely rather than mangling it', () => {
    expect(() =>
      splitUninstallSql("DO $$ BEGIN RAISE NOTICE 'x;y'; END $$;"),
    ).toThrow(/not in the shape this CLI can embed safely/)
  })
})

describe('Drizzle hints', () => {
  it('declares each twin with the builder for its mapped type, nullable', () => {
    expect(drizzleColumnLine('email', 'text')).toBe("email: text('email'),")
    expect(drizzleColumnLine('account_id', 'bigint')).toBe(
      "account_id: bigint('account_id', { mode: 'bigint' }),",
    )
    expect(drizzleColumnLine('created_at', 'timestamptz')).toBe(
      "created_at: timestamp('created_at', { withTimezone: true }),",
    )
    expect(drizzleColumnLine('score', 'double precision')).toBe(
      "score: doublePrecision('score'),",
    )
  })

  it('quotes awkward names safely', () => {
    expect(drizzleColumnLine("o'brien-x", 'text')).toBe(
      `"o'brien-x": text('o\\'brien-x'),`,
    )
  })

  it('lists each import once, sorted', () => {
    expect(drizzleImports(['text', 'jsonb', 'text', 'timestamptz'])).toEqual([
      'jsonb',
      'text',
      'timestamp',
    ])
  })
})
