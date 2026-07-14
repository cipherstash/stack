/**
 * End-to-end round-trip for the `eql_v3_boolean` domain against live
 * Postgres + EQL v3 + ZeroKMS.
 *
 * The v3 boolean domain is STORAGE-ONLY: it carries no search indexes
 * and advertises no query capabilities, so this file pins:
 *
 *   - INSERT + decrypt round-trip recovers `true` / `false`.
 *   - The ORM accessor binds NO cipherstash operator methods to the
 *     column (runtime trait dispatch: the codec has no traits, so
 *     `u.emailVerified.cipherstashEq` is `undefined`).
 *   - Calling the operator impls directly against the column throws
 *     `EncryptionOperatorError` (the per-domain capability gate).
 *
 * The refusal is a FEATURE, not a gap: a storage-only domain has no
 * searchable term to mint, and silently returning zero rows would be
 * worse than the loud error. Columns that need boolean equality
 * should model the flag differently (e.g. a text_eq status column).
 */

import {
  cipherstashV3QueryOperations,
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
  { id: 'e2e-bool-0', emailVerified: true },
  { id: 'e2e-bool-1', emailVerified: false },
  { id: 'e2e-bool-2', emailVerified: true },
  { id: 'e2e-bool-3', emailVerified: false },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(`${s.id}@example.com`),
    salary: EncryptedNumber.from(50_000),
    accountId: EncryptedBigInt.from(1_000_000n),
    birthday: EncryptedDate.from(new Date('1990-01-01')),
    emailVerified: EncryptedBoolean.from(s.emailVerified),
    preferences: EncryptedJson.from({ marker: 'bool' }),
  }
}

describe('eql_v3_boolean storage-only e2e (live PG + EQL v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
  })

  it('round-trips true and false through bulkEncrypt + bulkDecrypt', async () => {
    const rows = await db.orm.public.User.all()
    expect(rows).toHaveLength(SEED.length)
    await decryptAll(rows)
    const byId = new Map(rows.map((r) => [r.id, r] as const))
    for (const s of SEED) {
      const r = byId.get(s.id)
      expect(r, `seed row ${s.id} present`).toBeDefined()
      expect(r ? await r.emailVerified.decrypt() : undefined).toBe(
        s.emailVerified,
      )
    }
  })

  it('binds no cipherstash operator methods on the storage-only column', async () => {
    // Runtime trait dispatch: the eql_v3_boolean codec advertises no
    // cipherstash traits, so the model accessor never attaches the
    // operator methods. Every method the other suites use must be
    // absent here. (Type-level visibility agrees: none of these
    // compile on `u.emailVerified`, hence the untyped probe.)
    const observed: Record<string, string> = {}
    await db.orm.public.User.where((u) => {
      const probe = u.emailVerified as unknown as Record<string, unknown>
      for (const method of [
        'cipherstashEq',
        'cipherstashNe',
        'cipherstashInArray',
        'cipherstashNotInArray',
        'cipherstashGt',
        'cipherstashGte',
        'cipherstashLt',
        'cipherstashLte',
        'cipherstashBetween',
        'cipherstashNotBetween',
        'cipherstashIlike',
        'cipherstashNotIlike',
        'cipherstashJsonContains',
      ]) {
        observed[method] = typeof probe[method]
      }
      return u.id.isNotNull()
    }).all()
    for (const [method, type] of Object.entries(observed)) {
      expect(type, `${method} must not bind to eql_v3_boolean`).toBe(
        'undefined',
      )
    }
  })

  it('the operator impls throw EncryptionOperatorError against the boolean column', () => {
    const ops = cipherstashV3QueryOperations()
    // Reach the impls the way a custom builder could: with the column
    // expression captured from the typed SQL surface. The per-domain
    // capability gate must refuse the storage-only domain loudly.
    const attempts: ReadonlyArray<readonly [string, readonly unknown[]]> = [
      ['cipherstashEq', [true]],
      ['cipherstashNe', [false]],
      ['cipherstashInArray', [[true, false]]],
      ['cipherstashNotInArray', [[true]]],
      ['cipherstashGt', [false]],
      ['cipherstashBetween', [false, true]],
      ['cipherstashIlike', ['tru']],
      ['cipherstashJsonContains', [{ verified: true }]],
    ]
    db.sql.public.users
      .select((f) => {
        for (const [method, args] of attempts) {
          const op = ops[method]
          expect(op, `operator ${method} registered`).toBeDefined()
          expect(
            // The select-scope field is the same column-bound expression
            // the where-scope hands to operator impls; the impl parameter
            // type is wider than the scope field type, hence the cast.
            () => op?.impl(f.emailverified as never, ...(args as never[])),
            `${method} must refuse eql_v3_boolean`,
          ).toThrow(EncryptionOperatorError)
        }
        return { id: f.id }
      })
      .build()
  })
})
