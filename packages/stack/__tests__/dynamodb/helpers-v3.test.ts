/**
 * Pure tests for the EQL v3 attribute mapping (#657).
 *
 * The v2 equivalents live in `helpers.test.ts` and are the characterisation
 * baseline; this file asserts only what v3 changes:
 *
 *  - v3 scalars carry NO `k` discriminator, so the write path must key off the
 *    presence of a ciphertext. Gating on `k === 'ct'` (as the v2 code did)
 *    dropped every v3 scalar through to the nested-object branch and wrote it
 *    out as a raw map.
 *  - the read path synthesizes a v3 envelope (`v: 3`, no `k`) for a v3 table
 *    and a v2 one (`v: 2`, `k: 'ct'`) for a v2 table.
 *  - a v3 JSON document keeps `k: 'sv'`, which is mandatory — deserialization
 *    fails with "missing field `k`" without it.
 */
import { describe, expect, it } from 'vitest'
import {
  isV3Table,
  toEncryptedDynamoItem,
  toItemWithEqlPayloads,
} from '@/dynamodb/helpers'
import { encryptedTable, types } from '@/eql/v3'
import {
  encryptedColumn,
  encryptedField,
  encryptedTable as encryptedTableV2,
} from '@/schema'

const users = encryptedTable('users', {
  email: types.TextEq('email'),
  name: types.Text('name'),
  age: types.IntegerOrd('age'),
  meta: types.Json('meta'),
})

const encryptedAttrs = Object.keys(users.build().columns)

/** A v3 scalar payload as the FFI returns it — note the absent `k`. */
const scalar = (
  column: string,
  c: string,
  terms: Record<string, unknown> = {},
) => ({
  v: 3,
  i: { t: 'users', c: column },
  c,
  ...terms,
})

describe('isV3Table', () => {
  it('recognises a v3 table by its concrete-domain columns', () => {
    expect(isV3Table(users)).toBe(true)
  })

  it('recognises a flat v2 table', () => {
    const v2 = encryptedTableV2('users', {
      email: encryptedColumn('email').equality(),
    })

    expect(isV3Table(v2)).toBe(false)
  })

  it('recognises a v2 table whose columns are nested under a group', () => {
    const v2 = encryptedTableV2('users', {
      example: { protected: encryptedField('example.protected') },
    })

    expect(isV3Table(v2)).toBe(false)
  })
})

describe('toEncryptedDynamoItem with v3 payloads', () => {
  it('splits an untagged v3 scalar into __source and __hmac', () => {
    const result = toEncryptedDynamoItem(
      {
        pk: 'user#1',
        email: scalar('email', 'ciphertext', { hm: 'hmac-value' }),
      },
      encryptedAttrs,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email__source: 'ciphertext',
      email__hmac: 'hmac-value',
    })
  })

  it('stores a storage-only column with no search term', () => {
    const result = toEncryptedDynamoItem(
      { name: scalar('name', 'ciphertext') },
      encryptedAttrs,
    )

    expect(result).toEqual({ name__source: 'ciphertext' })
  })

  it('drops the ordering term of an *Ord domain — DynamoDB cannot use it', () => {
    const result = toEncryptedDynamoItem(
      { age: scalar('age', 'ciphertext', { op: 'ordering-term' }) },
      encryptedAttrs,
    )

    // Decryptable, but not orderable and not usable in a key condition.
    expect(result).toEqual({ age__source: 'ciphertext' })
    expect(result).not.toHaveProperty('age__hmac')
  })

  it('keeps the equality term of a TextSearch domain and drops the rest', () => {
    const result = toEncryptedDynamoItem(
      {
        email: scalar('email', 'ciphertext', {
          hm: 'hmac-value',
          op: 'ordering-term',
          bf: [1, 2, 3],
        }),
      },
      encryptedAttrs,
    )

    expect(result).toEqual({
      email__source: 'ciphertext',
      email__hmac: 'hmac-value',
    })
  })

  it('stores a v3 ste_vec document as its sv array', () => {
    const entries = [{ s: 'sel', c: 'ct', a: false, hm: 'h' }]
    const result = toEncryptedDynamoItem(
      { meta: { v: 3, k: 'sv', i: { t: 'users', c: 'meta' }, sv: entries } },
      encryptedAttrs,
    )

    expect(result).toEqual({ meta__source: entries })
  })
})

describe('toItemWithEqlPayloads for a v3 table', () => {
  it('rebuilds an untagged v3 scalar envelope', () => {
    const result = toItemWithEqlPayloads({ email__source: 'ciphertext' }, users)

    expect(result).toEqual({
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'ciphertext' },
    })
    expect(result.email).not.toHaveProperty('k')
  })

  it('rebuilds a v3 ste_vec envelope, keeping the mandatory k tag', () => {
    const entries = [{ s: 'sel', c: 'ct' }]
    const result = toItemWithEqlPayloads({ meta__source: entries }, users)

    expect(result).toEqual({
      meta: { i: { c: 'meta', t: 'users' }, v: 3, k: 'sv', sv: entries },
    })
  })

  it('still emits a v2 envelope for a v2 table', () => {
    const v2 = encryptedTableV2('users', {
      email: encryptedColumn('email').equality(),
    })

    expect(toItemWithEqlPayloads({ email__source: 'ct' }, v2)).toEqual({
      email: { i: { c: 'email', t: 'users' }, v: 2, k: 'ct', c: 'ct' },
    })
  })

  it('discards __hmac and passes plaintext through, as in v2', () => {
    const result = toItemWithEqlPayloads(
      { pk: 'user#1', email__source: 'ct', email__hmac: 'h', role: 'admin' },
      users,
    )

    expect(result).toEqual({
      pk: 'user#1',
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'ct' },
      role: 'admin',
    })
  })

  it('always emits both `v` and `i` — a payload missing either is returned raw', () => {
    const rebuilt = toItemWithEqlPayloads({ email__source: 'ct' }, users)
      .email as Record<string, unknown>

    // Not a cosmetic assertion: the FFI treats `v`/`i` as the "is this
    // encrypted" detection keys. A payload missing either is silently passed
    // through undecrypted rather than erroring.
    expect(rebuilt).toHaveProperty('v')
    expect(rebuilt).toHaveProperty('i')
  })

  it('round-trips a v3 item through both directions', () => {
    const stored = toEncryptedDynamoItem(
      {
        pk: 'user#1',
        email: scalar('email', 'email-ct', { hm: 'email-hmac' }),
        role: 'admin',
      },
      encryptedAttrs,
    )

    expect(toItemWithEqlPayloads(stored, users)).toEqual({
      pk: 'user#1',
      email: { i: { c: 'email', t: 'users' }, v: 3, c: 'email-ct' },
      role: 'admin',
    })
  })
})
