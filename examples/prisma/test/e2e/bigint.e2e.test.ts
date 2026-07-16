/**
 * End-to-end round-trip for the `eql_v3_bigint_ord` domain against
 * live Postgres + EQL v3 + ZeroKMS.
 *
 * Pins the v3 bigint pipeline's encrypt + decrypt + equality + range +
 * sort behaviour — INCLUDING losslessness beyond
 * `Number.MAX_SAFE_INTEGER`. The v2 example was capped at 2^53 − 1
 * (its SDK adapter converted `bigint → Number`); v3's protect-ffi
 * eqlVersion-3 wire handles `bigint` natively as a bounds-checked
 * int8, so 2^53 + 1 (unrepresentable as a JS number) must survive the
 * full round-trip and participate in equality/range/sort correctly.
 */

import {
  decryptAll,
  EncryptedBigInt,
  EncryptedBoolean,
  EncryptedDate,
  EncryptedJson,
  EncryptedNumber,
  EncryptedString,
  eqlAsc,
} from '@cipherstash/prisma-next/runtime'
import { beforeAll, describe, expect, it } from 'vitest'
import { db, ensureConnected, truncateUsers } from './harness'

// 2^53 + 1: NOT representable as a JS number. Losslessness here proves
// the pipeline is bigint end-to-end (protect-ffi's eqlVersion-3 int8).
const UNSAFE_BIG = 9_007_199_254_740_993n

const SEED = [
  { id: 'e2e-bigint-0', accountId: 1_000_000_000_001n },
  { id: 'e2e-bigint-1', accountId: 1_000_000_000_002n },
  { id: 'e2e-bigint-2', accountId: 9_000_000_000_000_000n },
  { id: 'e2e-bigint-3', accountId: UNSAFE_BIG },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(`${s.id}@example.com`),
    salary: EncryptedNumber.from(50_000),
    accountId: EncryptedBigInt.from(s.accountId),
    birthday: EncryptedDate.from(new Date('1990-01-01')),
    emailVerified: EncryptedBoolean.from(true),
    preferences: EncryptedJson.from({ marker: 'bigint' }),
  }
}

describe('EncryptedBigInt (eql_v3_bigint_ord) e2e (live PG + EQL v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
  })

  it('round-trips losslessly, including beyond Number.MAX_SAFE_INTEGER', async () => {
    const rows = await db.orm.public.User.all()
    expect(rows).toHaveLength(SEED.length)
    await decryptAll(rows)
    const byId = new Map(rows.map((r) => [r.id, r] as const))
    for (const s of SEED) {
      const r = byId.get(s.id)
      expect(r, `seed row ${s.id} present`).toBeDefined()
      const got = r ? await r.accountId.decrypt() : undefined
      expect(typeof got, `${s.id} must decrypt to a JS bigint`).toBe('bigint')
      expect(got).toBe(s.accountId)
    }
  })

  it('eqlEq selects exactly the row holding the unsafe-range value', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.accountId.eqlEq(UNSAFE_BIG),
    ).all()
    expect(rows.map((r) => r.id)).toEqual(['e2e-bigint-3'])
  })

  it('eqlGt filters by encrypted bigint numeric order', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.accountId.eqlGt(1_000_000_000_002n),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-bigint-2',
      'e2e-bigint-3',
    ])
  })

  it('eqlLte includes the equality boundary', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.accountId.eqlLte(1_000_000_000_002n),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-bigint-0',
      'e2e-bigint-1',
    ])
  })

  it('eqlBetween filters by encrypted bigint range', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.accountId.eqlBetween(1_000_000_000_002n, 9_000_000_000_000_000n),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-bigint-1',
      'e2e-bigint-2',
    ])
  })

  it('eqlIn returns rows whose value matches any of the supplied bigints', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.accountId.eqlIn([1_000_000_000_001n, UNSAFE_BIG]),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-bigint-0',
      'e2e-bigint-3',
    ])
  })

  it('eqlAsc orders by bigint value via the encrypted order term', async () => {
    // 2^53 + 1 = 9_007_199_254_740_993 > 9_000_000_000_000_000, so the
    // unsafe-range row sorts LAST — on the true int8 value, not a lossy
    // float projection.
    const rows = await db.orm.public.User.orderBy((u) =>
      eqlAsc(u.accountId),
    ).all()
    expect(rows.map((r) => r.id)).toEqual([
      'e2e-bigint-0',
      'e2e-bigint-1',
      'e2e-bigint-2',
      'e2e-bigint-3',
    ])
  })
})
