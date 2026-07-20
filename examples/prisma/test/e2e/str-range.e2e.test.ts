/**
 * End-to-end coverage for the `eql_v3_text_search` domain against
 * live Postgres + EQL v3 + ZeroKMS.
 *
 * `cipherstash.TextSearch()` is the maximal text domain:
 * equality + order/range (OPE) + free-text search (bloom match) on one
 * column. Pins:
 *   - Round-trip decrypt recovers the source strings.
 *   - `eqlEq` selects exactly the matching row.
 *   - `eqlGt('m')` filters lexicographically.
 *   - `eqlAsc` / `eqlDesc` order alphabetically
 *     via the encrypted order term.
 *   - `eqlMatch` — bloom-filter TOKEN containment
 *     (`eql_v3.matches`), not SQL ILIKE — coexists with the
 *     order-and-range operators on the same column.
 */

import 'dotenv/config'

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
  { id: 'e2e-str-0', email: 'alice@example.com' },
  { id: 'e2e-str-1', email: 'bob@example.com' },
  { id: 'e2e-str-2', email: 'mallory@example.com' },
  { id: 'e2e-str-3', email: 'zoe@other.test' },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(s.email),
    salary: EncryptedNumber.from(50_000),
    accountId: EncryptedBigInt.from(1_000_000n),
    birthday: EncryptedDate.from(new Date('1990-01-01')),
    emailVerified: EncryptedBoolean.from(true),
    preferences: EncryptedJson.from({ marker: 'str-range' }),
  }
}

describe('EncryptedString (eql_v3_text_search) e2e (live PG + EQL v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
  })

  it('round-trips an EncryptedString through bulkEncrypt + bulkDecrypt', async () => {
    const rows = await db.orm.public.User.all()
    expect(rows).toHaveLength(SEED.length)
    await decryptAll(rows)
    const byId = new Map(rows.map((r) => [r.id, r] as const))
    for (const s of SEED) {
      const r = byId.get(s.id)
      expect(r, `seed row ${s.id} present`).toBeDefined()
      expect(r ? await r.email.decrypt() : undefined).toBe(s.email)
    }
  })

  it('eqlEq selects exactly the matching row', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.email.eqlEq('mallory@example.com'),
    ).all()
    expect(rows.map((r) => r.id)).toEqual(['e2e-str-2'])
  })

  it('eqlGt filters lexicographically', async () => {
    const rows = await db.orm.public.User.where((u) => u.email.eqlGt('m')).all()
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-str-2', 'e2e-str-3'])
  })

  it('eqlAsc orders alphabetically via the encrypted order term', async () => {
    const rows = await db.orm.public.User.orderBy((u) => eqlAsc(u.email)).all()
    expect(rows.map((r) => r.id)).toEqual([
      'e2e-str-0',
      'e2e-str-1',
      'e2e-str-2',
      'e2e-str-3',
    ])
  })

  it('eqlDesc reverses the alphabetical order', async () => {
    const rows = await db.orm.public.User.orderBy((u) => eqlDesc(u.email)).all()
    expect(rows.map((r) => r.id)).toEqual([
      'e2e-str-3',
      'e2e-str-2',
      'e2e-str-1',
      'e2e-str-0',
    ])
  })

  it('eqlMatch (bloom token containment) coexists with order-and-range', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.email.eqlMatch('example.com'),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual([
      'e2e-str-0',
      'e2e-str-1',
      'e2e-str-2',
    ])
  })

  it('eqlMatch misses tokens absent from the ciphertext index', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.email.eqlMatch('nonexistent-token'),
    ).all()
    expect(rows).toHaveLength(0)
  })
})
