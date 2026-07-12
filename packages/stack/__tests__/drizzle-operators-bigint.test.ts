import { PgDialect, pgTable } from 'drizzle-orm/pg-core'
import { describe, expect, it, vi } from 'vitest'
import { createEncryptionOperators, encryptedType } from '@/drizzle'
import type { EncryptionClient } from '@/encryption'

// Regression coverage for the `bigint` (int8) plaintext path through the v3
// Drizzle operators. Before the fix, `toPlaintext` fell through to
// `String(value)`, so `ops.eq(bigintCol, 1n)` was encrypted as the TEXT "1" and
// silently mismatched the column's bigint domain. The operators must forward a
// native `bigint` to `encryptQuery` (whose term type is `Plaintext`), so
// protect-ffi 0.28 encrypts it against the int8 domain and bounds-checks it.

const ENCRYPTED_VALUE = '{"v":"encrypted-value"}'

function setup() {
  const encryptQuery = vi.fn(async (termsOrValue: unknown) =>
    Array.isArray(termsOrValue)
      ? { data: termsOrValue.map(() => ENCRYPTED_VALUE) }
      : { data: ENCRYPTED_VALUE },
  )
  const client = { encryptQuery } as unknown as EncryptionClient
  const encryptionOps = createEncryptionOperators(client)
  const dialect = new PgDialect()
  return { encryptQuery, encryptionOps, dialect }
}

const accounts = pgTable('accounts', {
  balance: encryptedType<bigint>('balance', {
    dataType: 'bigint',
    equality: true,
    orderAndRange: true,
  }),
})

describe('Drizzle v3 operators preserve bigint plaintext (int8 columns)', () => {
  it('eq forwards a native bigint to encryptQuery, not a String()-coerced value', async () => {
    const { encryptQuery, encryptionOps } = setup()

    await encryptionOps.eq(accounts.balance, 1n)

    expect(encryptQuery).toHaveBeenCalledTimes(1)
    const terms = encryptQuery.mock.calls[0]?.[0] as Array<{ value: unknown }>
    expect(terms).toHaveLength(1)
    expect(typeof terms[0]?.value).toBe('bigint')
    expect(terms[0]?.value).toBe(1n)
    // The pre-fix bug: a stringified bigint.
    expect(terms[0]?.value).not.toBe('1')
  })

  it('preserves i64 boundary magnitudes losslessly (beyond Number.MAX_SAFE_INTEGER)', async () => {
    const { encryptQuery, encryptionOps } = setup()
    const big = 9223372036854775807n // i64::MAX

    await encryptionOps.gt(accounts.balance, big)

    const terms = encryptQuery.mock.calls[0]?.[0] as Array<{ value: unknown }>
    expect(terms[0]?.value).toBe(big)
  })
})
