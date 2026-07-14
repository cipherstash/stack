/**
 * End-to-end round-trip for the `eql_v3_json` domain against live
 * Postgres + EQL v3 + ZeroKMS.
 *
 * v3 searchable JSON is containment-only: the ste_vec index answers
 * encrypted jsonb `@>` via `cipherstashJsonContains`, with the operand
 * minted as a ciphertext-free `eql_v3.query_jsonb` term. The v2
 * `cipherstashJsonbPathQueryFirst` / `cipherstashJsonbGet` /
 * `cipherstashJsonbPathExists` helpers do not exist in v3 (and with
 * them goes the v2 suite's "selector hashing" known-limitation skip —
 * containment works end-to-end).
 *
 * Pins:
 *   - INSERT + decrypt round-trip recovers the source JSON object.
 *   - `cipherstashJsonContains` selects by top-level, multi-key,
 *     nested-array, and nested-object containment (exact jsonb `@>`
 *     semantics, no false positives).
 *   - Negative cases: non-matching needles select zero rows.
 *   - The empty-object needle (`doc @> '{}'` — true for EVERY row) is
 *     rejected loudly instead of silently selecting the whole table.
 */

import {
  decryptAll,
  EncryptedBigInt,
  EncryptedBoolean,
  EncryptedDate,
  EncryptedJson,
  EncryptedNumber,
  EncryptedString,
  EncryptionOperatorError,
} from '@cipherstash/prisma-next/runtime'
import { beforeAll, describe, expect, it } from 'vitest'
import { db, ensureConnected, truncateUsers } from './harness'

const SEED = [
  {
    id: 'e2e-json-0',
    preferences: {
      theme: 'dark',
      notifications: true,
      locale: 'en-US',
      tags: ['alpha', 'beta'],
    },
  },
  {
    id: 'e2e-json-1',
    preferences: {
      theme: 'light',
      notifications: false,
      locale: 'de-DE',
      tags: ['beta'],
    },
  },
  {
    id: 'e2e-json-2',
    preferences: {
      theme: 'dark',
      notifications: true,
      nested: { level: 3, admin: true },
    },
  },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(`${s.id}@example.com`),
    salary: EncryptedNumber.from(50_000),
    accountId: EncryptedBigInt.from(1_000_000n),
    birthday: EncryptedDate.from(new Date('1990-01-01')),
    emailVerified: EncryptedBoolean.from(true),
    preferences: EncryptedJson.from(s.preferences),
  }
}

describe('EncryptedJson (eql_v3_json) e2e (live PG + EQL v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
  })

  it('round-trips an EncryptedJson through bulkEncrypt + bulkDecrypt', async () => {
    const rows = await db.orm.public.User.all()
    expect(rows).toHaveLength(SEED.length)
    await decryptAll(rows)
    const byId = new Map(rows.map((r) => [r.id, r] as const))
    for (const s of SEED) {
      const r = byId.get(s.id)
      expect(r, `seed row ${s.id} present`).toBeDefined()
      expect(await r!.preferences.decrypt()).toEqual(s.preferences)
    }
  })

  it('cipherstashJsonContains selects by top-level key/value containment', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({ theme: 'dark' }),
    ).all()
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-json-0', 'e2e-json-2'])
  })

  it('cipherstashJsonContains requires ALL needle keys (multi-key containment)', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({
        theme: 'dark',
        locale: 'en-US',
      }),
    ).all()
    expect(rows.map((r) => r.id)).toEqual(['e2e-json-0'])
  })

  it('cipherstashJsonContains matches array-element containment', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({ tags: ['beta'] }),
    ).all()
    // jsonb `@>`: ['alpha','beta'] ⊇ ['beta'] and ['beta'] ⊇ ['beta'].
    expect(rows.map((r) => r.id).sort()).toEqual(['e2e-json-0', 'e2e-json-1'])
  })

  it('cipherstashJsonContains matches nested-object containment', async () => {
    const rows = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({ nested: { admin: true } }),
    ).all()
    expect(rows.map((r) => r.id)).toEqual(['e2e-json-2'])
  })

  it('cipherstashJsonContains returns zero rows for non-matching needles', async () => {
    const wrongValue = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({ theme: 'sepia' }),
    ).all()
    expect(wrongValue).toHaveLength(0)

    const wrongKey = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({ timezone: 'UTC' }),
    ).all()
    expect(wrongKey).toHaveLength(0)

    const partialNested = await db.orm.public.User.where((u) =>
      u.preferences.cipherstashJsonContains({
        nested: { level: 3, admin: false },
      }),
    ).all()
    expect(partialNested).toHaveLength(0)
  })

  it('rejects the match-everything empty-object needle loudly', () => {
    expect(() =>
      db.orm.public.User.where((u) =>
        u.preferences.cipherstashJsonContains({}),
      ),
    ).toThrow(EncryptionOperatorError)
  })
})
