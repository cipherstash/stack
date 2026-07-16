/**
 * End-to-end mixed-domain query against live Postgres + EQL v3 +
 * ZeroKMS.
 *
 * Pins the cross-domain invariants:
 *   - A single query that touches multiple cipherstash v3 columns of
 *     different domains in WHERE + ORDER BY succeeds end-to-end.
 *   - The bulk-encrypt middleware batches every operand into the
 *     minimum number of framework-SDK crossings — one `bulkEncrypt`
 *     seam call per `(table, column)` group. (Inside the v3 SDK
 *     adapter, WHERE operands route through `encryptQuery` as
 *     ciphertext-free query terms; the seam count is what the
 *     middleware controls and what this suite observes.)
 *
 * Crossing counts are observed by wrapping a fresh `CipherstashSdk`
 * (built from `cipherstashFromStackV3({ contractJson }).encryptionClient`
 * via `createCipherstashV3Sdk`) with a counting decorator and threading
 * the wrapped instance into a private `db` runtime. Concretely:
 *
 *   - WHERE touches `email` (text_search) + `salary` (double_ord) +
 *     `birthday` (date_ord) — three cipher columns, so **3 bulkEncrypt
 *     seam calls** for the search terms. (`emailVerified` cannot
 *     appear: `eql_v3_boolean` is storage-only — see bool.e2e.test.ts.)
 *   - The query is a read so no row-write envelopes are encrypted.
 *   - The result rows carry encrypted values across six columns; a
 *     follow-up `decryptAll(rows)` produces **6 bulkDecrypt calls**
 *     (one per `(table, column)` group spanning the result set).
 */

import {
  bulkEncryptMiddlewareV3,
  createCipherstashV3RuntimeDescriptor,
  decryptAll,
  EncryptedBigInt,
  EncryptedBoolean,
  EncryptedDate,
  EncryptedJson,
  EncryptedNumber,
  EncryptedString,
  eqlAsc,
} from '@cipherstash/prisma-next/runtime'
import {
  cipherstashFromStackV3,
  createCipherstashV3Sdk,
  deriveStackSchemasV3,
} from '@cipherstash/prisma-next/v3'
import postgres from '@prisma-next/postgres/runtime'
import { and } from '@prisma-next/sql-orm-client'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { Contract } from '../../src/prisma/contract.d'
import contractJson from '../../src/prisma/contract.json' with { type: 'json' }
import { truncateUsers } from './harness'

const SEED = [
  {
    id: 'e2e-mixed-0',
    email: 'alice@example.com',
    salary: 50_000,
    birthday: new Date('1985-01-01'),
    emailVerified: true,
  },
  {
    id: 'e2e-mixed-1',
    email: 'bob@example.com',
    salary: 110_000,
    birthday: new Date('1990-06-15'),
    emailVerified: true,
  },
  {
    id: 'e2e-mixed-2',
    email: 'carol@example.com',
    salary: 90_000,
    birthday: new Date('1980-03-22'),
    emailVerified: false,
  },
  {
    id: 'e2e-mixed-3',
    email: 'dave@otherorg.test',
    salary: 145_000,
    birthday: new Date('1978-11-30'),
    emailVerified: true,
  },
] as const

function seedRow(s: (typeof SEED)[number]) {
  return {
    id: s.id,
    email: EncryptedString.from(s.email),
    salary: EncryptedNumber.from(s.salary),
    accountId: EncryptedBigInt.from(1_000_000n),
    birthday: EncryptedDate.from(s.birthday),
    emailVerified: EncryptedBoolean.from(s.emailVerified),
    preferences: EncryptedJson.from({ marker: 'mixed' }),
  }
}

/**
 * Build a counting wrapper around a base SDK so we can observe
 * `bulkEncrypt` / `bulkDecrypt` seam-call counts independent of the
 * harness's shared `db` instance.
 */
function wrapWithCounting(base: ReturnType<typeof createCipherstashV3Sdk>) {
  let bulkEncryptCalls = 0
  let bulkDecryptCalls = 0
  return {
    sdk: {
      ...base,
      async bulkEncrypt(args: Parameters<typeof base.bulkEncrypt>[0]) {
        bulkEncryptCalls += 1
        return base.bulkEncrypt(args)
      },
      async bulkDecrypt(args: Parameters<typeof base.bulkDecrypt>[0]) {
        bulkDecryptCalls += 1
        return base.bulkDecrypt(args)
      },
    },
    counts: {
      get bulkEncrypt() {
        return bulkEncryptCalls
      },
      get bulkDecrypt() {
        return bulkDecryptCalls
      },
      reset() {
        bulkEncryptCalls = 0
        bulkDecryptCalls = 0
      },
    },
  }
}

describe('Mixed-domain e2e (live PG + EQL v3 + ZeroKMS)', () => {
  // Use a private `db` instance with a counting SDK so the crossing
  // assertions are insulated from any other test file that may have
  // mutated the harness's shared client.
  const url =
    process.env['DATABASE_URL'] ??
    'postgres://cipherstash:cipherstash@localhost:54329/cipherstash_e2e'
  let counting: ReturnType<typeof wrapWithCounting>
  let db: ReturnType<typeof postgres<Contract>>
  let runtime: { close(): Promise<void> } | undefined

  beforeAll(async () => {
    // Reuse the encryption client from `cipherstashFromStackV3` so the
    // counting wrapper observes the same ZeroKMS workspace + schema
    // surface the example app would in production. Re-derive the v3
    // stack schemas from `contractJson` to satisfy
    // `createCipherstashV3Sdk`'s `(client, schemas)` contract.
    const { encryptionClient } = await cipherstashFromStackV3({ contractJson })
    const schemas = deriveStackSchemasV3(contractJson)
    const baseSdk = createCipherstashV3Sdk(encryptionClient, schemas)
    counting = wrapWithCounting(baseSdk)
    db = postgres<Contract>({
      contractJson,
      extensions: [createCipherstashV3RuntimeDescriptor({ sdk: counting.sdk })],
      middleware: [bulkEncryptMiddlewareV3(counting.sdk)],
    })
    runtime = (await db.connect({ url })) as { close(): Promise<void> }
    await truncateUsers()
    await Promise.all(SEED.map((s) => db.orm.public.User.create(seedRow(s))))
    counting.counts.reset()
  })

  afterAll(async () => {
    if (runtime) {
      await runtime.close()
    }
  })

  it('executes a three-column WHERE + order-term read end-to-end', async () => {
    const rows = await db.orm.public.User.where((u) =>
      and(
        u.email.eqlMatch('example.com'),
        u.salary.eqlGt(75_000),
        u.birthday.eqlLt(new Date('2000-01-01')),
      ),
    )
      .orderBy((u) => eqlAsc(u.salary))
      .all()

    // carol (90k) and bob (110k) survive all three predicates, ordered
    // by ascending encrypted salary; alice's salary is below the 75k
    // cutoff and dave's email `dave@otherorg.test` carries no
    // example.com token.
    expect(rows.map((r) => r.id)).toEqual(['e2e-mixed-2', 'e2e-mixed-1'])
  })

  it('groups operand encrypts: one bulkEncrypt seam call per (table, column)', async () => {
    counting.counts.reset()
    await db.orm.public.User.where((u) =>
      and(
        u.email.eqlMatch('example.com'),
        u.salary.eqlGt(75_000),
        u.birthday.eqlLt(new Date('2000-01-01')),
      ),
    )
      .orderBy((u) => eqlAsc(u.salary))
      .all()
    // Three distinct (users, <column>) groups in the WHERE — one
    // framework-SDK `bulkEncrypt` crossing per group (each routed to
    // `encryptQuery` inside the v3 adapter). ORDER BY is an order-term
    // extraction over the column itself (no operand to encrypt). No
    // row writes, so no additional crossings.
    expect(counting.counts.bulkEncrypt).toBe(3)
  })

  it('groups result decrypts: one bulkDecrypt per (table, column)', async () => {
    counting.counts.reset()
    const rows = await db.orm.public.User.all()
    await decryptAll(rows)
    // Six encrypted columns × N rows ⇒ exactly 6 `bulkDecrypt` calls
    // (one per `(users, <column>)` group).
    expect(counting.counts.bulkDecrypt).toBe(6)
  })
})
