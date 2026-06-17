/**
 * End-to-end domain matrix for EQL v3 `EncryptedStringV3` against live Postgres +
 * the eql_v3 bundle + ZeroKMS.
 *
 * Each `UserV3` row sets email = bio = name = label, so one label drives all three
 * index columns:
 *   - email (text_eq)    — cipherstashEq / Ne / InArray / NotInArray
 *   - bio   (text_match) — cipherstashIlike / NotIlike (containment)
 *   - name  (text_ord)   — cipherstashLt/Lte/Gt/Gte/Between + asc/desc order
 *
 * Gated on DATABASE_URL (set by global-setup once the harness Postgres + ZeroKMS
 * credentials are configured); skips cleanly otherwise.
 */
import { EncryptedString, decryptAll } from '@cipherstash/prisma-next/runtime'
import { beforeAll, describe, expect, it } from 'vitest'
import { db, ensureConnected, truncateUserV3 } from './harness'
import {
  oracleBetween,
  oracleContains,
  oracleEq,
  oracleInArray,
  oracleLt,
  oracleNe,
  v3Seed,
} from './helpers/eql-v3-seed'

const dbUrl = process.env['DATABASE_URL']

function seedRow(s: (typeof v3Seed)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(s.label),
    bio: EncryptedString.from(s.label),
    name: EncryptedString.from(s.label),
  }
}

describe.skipIf(!dbUrl)('EQL v3 String e2e (live PG + eql_v3 + ZeroKMS)', () => {
  beforeAll(async () => {
    await ensureConnected()
    truncateUserV3()
    await Promise.all(v3Seed.map((s) => db.orm.UserV3.create(seedRow(s))))
  })

  it('eq round-trips on text_eq; decrypt returns the plaintext', async () => {
    const rows = await db.orm.UserV3.where((u) => u.email.cipherstashEq('aardvark')).all()
    await decryptAll(rows)
    expect(rows.map((r) => r.id).sort()).toEqual(oracleEq('aardvark'))
    expect(await rows[0]!.email.decrypt()).toBe('aardvark')
  })

  it('HMAC determinism: a second identical plaintext also matches eq', async () => {
    // 'aard' and 'aardvark' are distinct; eq('aard') matches exactly the 'aard' row.
    const rows = await db.orm.UserV3.where((u) => u.email.cipherstashEq('aard')).all()
    expect(rows.map((r) => r.id).sort()).toEqual(oracleEq('aard'))
  })

  it('ne excludes the matching row', async () => {
    const rows = await db.orm.UserV3.where((u) => u.email.cipherstashNe('banana')).all()
    expect(rows.map((r) => r.id).sort()).toEqual(oracleNe('banana'))
  })

  it('inArray / notInArray on text_eq', async () => {
    const inRows = await db.orm.UserV3.where((u) => u.email.cipherstashInArray(['aard', 'cherry'])).all()
    expect(inRows.map((r) => r.id).sort()).toEqual(oracleInArray(['aard', 'cherry']))
    const notInRows = await db.orm.UserV3.where((u) => u.email.cipherstashNotInArray(['aard', 'cherry'])).all()
    expect(notInRows.map((r) => r.id).sort()).toEqual(
      v3Seed.filter((r) => !['aard', 'cherry'].includes(r.label)).map((r) => r.id).sort(),
    )
  })

  it('lt / between on text_ord match the ord oracle', async () => {
    const lt = await db.orm.UserV3.where((u) => u.name.cipherstashLt('banana')).all()
    expect(lt.map((r) => r.id).sort()).toEqual(oracleLt('banana'))
    const between = await db.orm.UserV3.where((u) => u.name.cipherstashBetween('aardvark', 'cherry')).all()
    expect(between.map((r) => r.id).sort()).toEqual(oracleBetween('aardvark', 'cherry'))
  })

  it('ilike (containment) matches the shared-trigram pair on text_match', async () => {
    // 'aard' is a substring of both 'aardvark' and 'aard'.
    const rows = await db.orm.UserV3.where((u) => u.bio.cipherstashIlike('aard')).all()
    expect(rows.map((r) => r.id).sort()).toEqual(oracleContains('aard'))
  })

  it('notIlike excludes the matching rows on text_match', async () => {
    const rows = await db.orm.UserV3.where((u) => u.bio.cipherstashNotIlike('aard')).all()
    const expected = v3Seed.filter((r) => !r.label.includes('aard')).map((r) => r.id).sort()
    expect(rows.map((r) => r.id).sort()).toEqual(expected)
  })

  it('insert + decrypt round-trips a freshly-created v3 row (UserV3 columns are NOT NULL)', async () => {
    await db.orm.UserV3.create({
      id: 'e2e-strv3-extra',
      email: EncryptedString.from('present'),
      bio: EncryptedString.from('present'),
      name: EncryptedString.from('present'),
    })
    const rows = await db.orm.UserV3.where((u) => u.email.cipherstashEq('present')).all()
    await decryptAll(rows)
    expect(await rows[0]!.email.decrypt()).toBe('present')
  })

  // Negative case proving the domain seam protects against silent coercion: the
  // runtime mismatch guard rejects cipherstashGt (orderAndRange) on the
  // equality-indexed email column. The guard throws SYNCHRONOUSLY while `.where`
  // builds the predicate, before any query runs.
  it('an ordering operator against a text_eq column raises (no ord_term for that domain)', () => {
    expect(() => db.orm.UserV3.where((u) => u.email.cipherstashGt('aardvark'))).toThrow(/orderAndRange/)
  })
})
