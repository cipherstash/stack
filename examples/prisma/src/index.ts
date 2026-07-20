/**
 * @cipherstash/prisma-next example — end-to-end demo (EQL v3).
 *
 * Exercises one v3 domain per plaintext family, plus the
 * trait-dispatched predicate operators and the encrypted ORDER BY
 * helpers, against a real Postgres + EQL v3 database.
 *
 * The bulk-encrypt middleware groups every plaintext placeholder into
 * the minimum number of SDK crossings per query: row payloads go
 * through one storage `bulkEncrypt` per `(table, column)` group, and
 * operator operands are minted as ciphertext-free QUERY TERMS via
 * `encryptQuery` (batched per flavour). `decryptAll(rows)` mirrors the
 * read side with one `bulkDecrypt` call per `(table, column)` group
 * across the result set.
 *
 * Column surface (the constructor IS the capability set in v3):
 *
 *   - email         eql_v3_text_search — eq/range/free-text + ORDER BY
 *   - salary        eql_v3_double_ord  — eq + range + ORDER BY
 *   - accountId     eql_v3_bigint_ord  — eq + range + ORDER BY
 *   - birthday      eql_v3_date_ord    — eq + range + ORDER BY
 *   - emailVerified eql_v3_boolean     — STORAGE-ONLY (no operators)
 *   - preferences   eql_v3_json_search        — eqlJsonContains (@>)
 *
 * Prerequisites:
 *
 *   1. A Postgres database with the EQL v3 bundle installed. The
 *      extension contributes its own contract space at
 *      `migrations/cipherstash/` which installs the EQL bundles
 *      (v2 + v3 baselines) alongside the application schema —
 *      `pnpm migration:apply` runs it for you.
 *   2. A CipherStash workspace + ZeroKMS credentials. Run
 *      `stash auth login` once, or populate `CS_WORKSPACE_CRN`,
 *      `CS_CLIENT_ID`, `CS_CLIENT_KEY`, and `CS_CLIENT_ACCESS_KEY`
 *      in `.env` (see `.env.example`).
 *   3. `DATABASE_URL` in `.env` pointing at the database from (1).
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
} from '@cipherstash/prisma-next/runtime'

import { db } from './db'

interface UserSeed {
  readonly id: string
  readonly email: string
  readonly salary: number
  readonly accountId: bigint
  readonly birthday: Date
  readonly emailVerified: boolean
  readonly preferences: {
    readonly theme: string
    readonly notifications: boolean
  }
}

const SEED_USERS: readonly UserSeed[] = [
  {
    id: 'user-0',
    email: 'alice@example.com',
    salary: 95_000,
    accountId: 100_000_000_001n,
    birthday: new Date('1990-04-12'),
    emailVerified: true,
    preferences: { theme: 'dark', notifications: true },
  },
  {
    id: 'user-1',
    email: 'bob@example.com',
    salary: 110_000,
    accountId: 100_000_000_002n,
    birthday: new Date('1985-09-23'),
    emailVerified: true,
    preferences: { theme: 'light', notifications: false },
  },
  {
    id: 'user-2',
    email: 'carol@example.com',
    salary: 75_000,
    accountId: 100_000_000_003n,
    birthday: new Date('1995-01-07'),
    emailVerified: false,
    preferences: { theme: 'dark', notifications: true },
  },
  {
    id: 'user-3',
    email: 'dave@otherorg.test',
    salary: 145_000,
    accountId: 100_000_000_004n,
    birthday: new Date('1978-11-30'),
    emailVerified: true,
    preferences: { theme: 'light', notifications: true },
  },
]

async function main() {
  const url = process.env['DATABASE_URL']
  if (!url) {
    console.error(
      'Set DATABASE_URL in your environment (e.g. .env) before running this demo.',
    )
    process.exit(1)
  }

  const runtime = await db.connect({ url })
  try {
    await clearUsers()
    await insertUsers()
    await searchByEq()
    await searchByMatchAndDecrypt()
    await rangeQueryOnSalary()
    await betweenQueryOnBirthday()
    await inArrayQueryOnAccountId()
    await decryptStorageOnlyBoolean()
    await jsonContainmentOnPreferences()
    await sortByEmailAsc()
  } finally {
    await runtime.close()
  }
}

async function clearUsers(): Promise<void> {
  const removed = await db.orm.public.User.where((u) =>
    u.id.isNotNull(),
  ).deleteCount()
  if (removed > 0) {
    console.log(`--- Cleanup ---\nRemoved ${removed} existing user row(s).\n`)
  }
}

async function insertUsers(): Promise<void> {
  console.log('--- Insert (mixed-domain round-trip) ---')
  await Promise.all(
    SEED_USERS.map((seed) =>
      db.orm.public.User.create({
        id: seed.id,
        email: EncryptedString.from(seed.email),
        salary: EncryptedNumber.from(seed.salary),
        accountId: EncryptedBigInt.from(seed.accountId),
        birthday: EncryptedDate.from(seed.birthday),
        emailVerified: EncryptedBoolean.from(seed.emailVerified),
        preferences: EncryptedJson.from(seed.preferences),
      }),
    ),
  )
  console.log(
    `Inserted ${SEED_USERS.length} rows across six cipherstash v3 domains.`,
  )
}

async function searchByEq(): Promise<void> {
  console.log('\n--- eqlEq (text_search equality) ---')
  const rows = await db.orm.public.User.where((u) =>
    u.email.eqlEq('alice@example.com'),
  ).all()
  console.log(`Found ${rows.length} row(s) for alice@example.com.`)
  await decryptAll(rows)
  for (const row of rows) {
    console.log(`  ${row.id}: ${await row.email.decrypt()}`)
  }
}

async function searchByMatchAndDecrypt(): Promise<void> {
  console.log('\n--- eqlMatch (text_search free-text tokens) ---')
  // v3 free-text search is bloom-filter TOKEN matching (eql_v3.matches),
  // not SQL ILIKE: the needle's tokens must appear in the ciphertext's
  // index. 'example.com' matches the three @example.com addresses.
  const rows = await db.orm.public.User.where((u) =>
    u.email.eqlMatch('example.com'),
  ).all()
  console.log(`Found ${rows.length} row(s) whose email contains example.com.`)
  await decryptAll(rows)
  for (const row of rows) {
    console.log(`  ${row.id}: ${await row.email.decrypt()}`)
  }
}

async function rangeQueryOnSalary(): Promise<void> {
  console.log('\n--- eqlGt (double_ord order-and-range) ---')
  const rows = await db.orm.public.User.where((u) =>
    u.salary.eqlGt(100_000),
  ).all()
  console.log(`Found ${rows.length} user(s) with salary > 100,000.`)
  await decryptAll(rows)
  for (const row of rows) {
    console.log(`  ${row.id}: salary=${await row.salary.decrypt()}`)
  }
}

async function betweenQueryOnBirthday(): Promise<void> {
  console.log('\n--- eqlBetween (date_ord order-and-range) ---')
  const lower = new Date('1985-01-01')
  const upper = new Date('1995-12-31')
  const rows = await db.orm.public.User.where((u) =>
    u.birthday.eqlBetween(lower, upper),
  ).all()
  console.log(`Found ${rows.length} user(s) born between 1985 and 1995.`)
}

async function inArrayQueryOnAccountId(): Promise<void> {
  console.log('\n--- eqlIn (bigint_ord equality) ---')
  const rows = await db.orm.public.User.where((u) =>
    u.accountId.eqlIn([100_000_000_001n, 100_000_000_004n]),
  ).all()
  console.log(
    `Found ${rows.length} user(s) whose accountId is in the supplied array.`,
  )
}

async function decryptStorageOnlyBoolean(): Promise<void> {
  console.log('\n--- eql_v3_boolean (storage-only round-trip) ---')
  // The v3 boolean domain carries no search indexes: it round-trips
  // true/false losslessly but surfaces NO cipherstash operators —
  // calling one would throw EncryptionOperatorError. Filter on a
  // searchable column and decrypt the boolean from the result set.
  const rows = await db.orm.public.User.where((u) =>
    u.email.eqlEq('carol@example.com'),
  ).all()
  await decryptAll(rows)
  for (const row of rows) {
    console.log(
      `  ${row.id}: emailVerified=${await row.emailVerified.decrypt()}`,
    )
  }
}

async function jsonContainmentOnPreferences(): Promise<void> {
  console.log('\n--- eqlJsonContains (encrypted jsonb @>) ---')
  const rows = await db.orm.public.User.where((u) =>
    u.preferences.eqlJsonContains({ theme: 'dark' }),
  ).all()
  console.log(`Found ${rows.length} user(s) with a dark-theme preference.`)
  await decryptAll(rows)
  for (const row of rows) {
    console.log(
      `  ${row.id}: ${JSON.stringify(await row.preferences.decrypt())}`,
    )
  }
}

async function sortByEmailAsc(): Promise<void> {
  console.log('\n--- eqlAsc (encrypted order-term ORDER BY) ---')
  const rows = await db.orm.public.User.orderBy((u) => eqlAsc(u.email)).all()
  await decryptAll(rows)
  for (const row of rows) {
    console.log(`  ${row.id}: email=${await row.email.decrypt()}`)
  }
}

await main()
