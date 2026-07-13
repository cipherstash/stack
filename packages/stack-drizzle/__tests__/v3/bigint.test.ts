import { type SQL, sql } from 'drizzle-orm'
import { integer, PgDialect, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it, vi } from 'vitest'
import { getEqlV3Column, isEqlV3Column } from '../../src/v3/column'
import {
  createEncryptionOperatorsV3,
  EncryptionOperatorError,
} from '../../src/v3/operators'
import { types } from '../../src/v3/types'

// A representative query TERM — what `client.encryptQuery` returns for a bigint
// operand: a ciphertext-free term, deliberately NOT a plaintext bigint.
const TERM = { hm: 'h', v: 3 }
const TERM_JSON = JSON.stringify(TERM)

function chainable(result: unknown) {
  const op = result as {
    withLockContext: ReturnType<typeof vi.fn>
    audit: ReturnType<typeof vi.fn>
  }
  op.withLockContext = vi.fn(() => op)
  op.audit = vi.fn(() => op)
  return op
}

function setup() {
  const encryptQuery = vi.fn(() => chainable(Promise.resolve({ data: TERM })))
  const ops = createEncryptionOperatorsV3({ encryptQuery })
  const dialect = new PgDialect()
  const render = (s: SQL) => dialect.sqlToQuery(s)
  return { ops, encryptQuery, render }
}

// A statically-typed table via the drizzle `types` namespace (no dynamic
// matrix, no casts) — the column set is known at compile time.
const accounts = pgTable('accounts', {
  id: integer().primaryKey(),
  balance: types.BigintOrd('balance'),
  ledgerId: types.BigintEq('ledger_id'),
  archived: types.Bigint('archived'),
})

describe('v3 drizzle bigint columns', () => {
  it('detects a bigint column and reports its concrete public.eql_v3_bigint domain', () => {
    const storage = types.Bigint('n')
    const ord = types.BigintOrd('n_ord')

    expect(isEqlV3Column(storage)).toBe(true)
    expect(getEqlV3Column('n', storage)?.getEqlType()).toBe(
      'public.eql_v3_bigint',
    )
    expect(getEqlV3Column('n_ord', ord)?.getEqlType()).toBe(
      'public.eql_v3_bigint_ord',
    )
  })

  it('emits the concrete public.eql_v3_bigint* SQL type through pgTable', () => {
    expect(accounts.balance.getSQLType()).toBe('public.eql_v3_bigint_ord')
    expect(accounts.ledgerId.getSQLType()).toBe('public.eql_v3_bigint_eq')
    expect(accounts.archived.getSQLType()).toBe('public.eql_v3_bigint')
  })

  it('encrypts a native bigint operand for eq without JSON-stringifying it', async () => {
    const { ops, encryptQuery, render } = setup()
    // A value beyond Number.MAX_SAFE_INTEGER to prove the bigint is passed
    // through untouched (a JSON.stringify of a bigint would have thrown).
    const value = 9223372036854775807n
    const q = render(await ops.eq(accounts.ledgerId, value))

    expect(q.sql).toContain(
      'eql_v3.eq("accounts"."ledger_id", $1::eql_v3.query_bigint_eq)',
    )
    expect(q.params).toEqual([TERM_JSON])
    expect(encryptQuery.mock.calls[0]?.[0]).toBe(value)
  })

  it('emits ordering and range operators for a bigint_ord column', async () => {
    const { ops, render } = setup()

    const gt = render(await ops.gt(accounts.balance, 10n))
    expect(gt.sql).toContain(
      'eql_v3.gt("accounts"."balance", $1::eql_v3.query_bigint_ord)',
    )

    const between = render(await ops.between(accounts.balance, -5n, 5n))
    expect(between.sql).toContain(
      'eql_v3.gte("accounts"."balance", $1::eql_v3.query_bigint_ord)',
    )
    expect(between.sql).toContain(
      'eql_v3.lte("accounts"."balance", $2::eql_v3.query_bigint_ord)',
    )

    const asc = render(ops.asc(accounts.balance))
    expect(asc.sql).toContain('eql_v3.ord_term("accounts"."balance")')
  })

  it('rejects equality/ordering on a storage-only bigint column', async () => {
    const { ops } = setup()
    await expect(ops.eq(accounts.archived, 1n)).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
    expect(() => ops.asc(accounts.archived)).toThrow(EncryptionOperatorError)
  })

  it('rejects a bare SQL expression that is not an encrypted column', async () => {
    const { ops } = setup()
    await expect(ops.eq(sql`1`, 1n)).rejects.toBeInstanceOf(
      EncryptionOperatorError,
    )
  })
})
