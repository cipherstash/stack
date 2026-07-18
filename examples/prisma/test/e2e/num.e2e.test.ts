/**
 * End-to-end round-trip for the `eql_v3_double_ord` domain against
 * live Postgres + EQL v3 + ZeroKMS.
 *
 * Pins:
 *   - INSERT + decrypt round-trip recovers the source numbers (v3
 *     `number`-castAs domains decrypt to the `EncryptedNumber`
 *     envelope, not the v2 `EncryptedDouble`).
 *   - `eqlGt`, `eqlGte`, `eqlLt`,
 *     `eqlLte`, `eqlBetween` each filter rows
 *     correctly against the OPE-indexed encrypted column
 *     (`eql_v3.gt(col, $n::eql_v3.query_double_ord)` and friends).
 *   - `eqlAsc` / `eqlDesc` produce numerically
 *     sorted results. Unlike v2's bare-column ORDER BY, v3 sorting
 *     extracts the encrypted order term (`eql_v3.ord_term(col)`) —
 *     the domain has no cross-row comparison operators of its own.
 *
 * Seed: four rows with file-scoped ID prefix `e2e-num-`. The
 * `beforeAll` truncates `users` first so the file's assertions
 * count exact-match cardinalities (not "at-least-N").
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
  eqlDesc,
} from '@cipherstash/prisma-next/runtime'
import { beforeAll, describe, expect, it } from 'vitest'
import { db, ensureConnected, truncateUsers } from './harness'

const SEED = [
  { id: 'e2e-num-0', salary: 50_000 },
  { id: 'e2e-num-1', salary: 95_000 },
  { id: 'e2e-num-2', salary: 120_000 },
  { id: 'e2e-num-3', salary: 200_000 },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(`${s.id}@example.com`),
    salary: EncryptedNumber.from(s.salary),
    accountId: EncryptedBigInt.from(1_000_000n),
    birthday: EncryptedDate.from(new Date('1990-01-01')),
    emailVerified: EncryptedBoolean.from(true),
    preferences: EncryptedJson.from({ marker: 'num' }),
  }
}

describe('EncryptedNumber (eql_v3_double_ord) e2e (live PG + EQL v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
  })

  it('round-trips an EncryptedNumber through bulkEncrypt + bulkDecrypt', async () => {
    const rows = await db.orm.public.User.all()
    expect(rows).toHaveLength(SEED.length)
    await decryptAll(rows)
    const byId = new Map(rows.map((r) => [r.id, r] as const))
    for (const s of SEED) {
      const r = byId.get(s.id)
      expect(r, `seed row ${s.id} present`).toBeDefined()
      expect(await r!.salary.decrypt()).toBe(s.salary)
    }
  })

  it('eqlGt filters by encrypted numeric order', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.salary.eqlGt(95_000),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-num-2', 'e2e-num-3'])
  })

  it('eqlGte includes the equality boundary', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.salary.eqlGte(95_000),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-num-1',
      'e2e-num-2',
      'e2e-num-3',
    ])
  })

  it('eqlLt filters strict-less-than', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.salary.eqlLt(120_000),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-num-0', 'e2e-num-1'])
  })

  it('eqlLte includes the equality boundary', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.salary.eqlLte(120_000),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-num-0',
      'e2e-num-1',
      'e2e-num-2',
    ])
  })

  it('eqlBetween bounds inclusively on both sides', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.salary.eqlBetween(95_000, 120_000),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-num-1', 'e2e-num-2'])
  })

  it('eqlAsc orders by numeric value via the encrypted order term', async () => {
    const rows = await db.orm.public.User.orderBy((u) => eqlAsc(u.salary)).all()
    expect(rows.map((r) => r.id)).toEqual([
      'e2e-num-0',
      'e2e-num-1',
      'e2e-num-2',
      'e2e-num-3',
    ])
  })

  it('eqlDesc reverses the ascending order', async () => {
    const rows = await db.orm.public.User.orderBy((u) =>
      eqlDesc(u.salary),
    ).all()
    expect(rows.map((r) => r.id)).toEqual([
      'e2e-num-3',
      'e2e-num-2',
      'e2e-num-1',
      'e2e-num-0',
    ])
  })
})
