/**
 * Live, identity-bound querying through the v3 Drizzle operator path.
 *
 * `matrix-identity-live.test.ts` proves lock context round-trips through the
 * typed CLIENT (`encryptModel`/`decryptModel`), and `operators.test.ts` proves
 * the Drizzle operators FORWARD `lockContext`/`audit` — but only against a
 * MOCKED FFI. Nothing exercises the one end-to-end shape that matters most:
 * seed rows bound to an identity, then query them with `ops.eq(col, value,
 * { lockContext })` against a real database and assert the encrypted term
 * actually matches the stored row and decrypts.
 *
 * Wiring mirrors `lock-context.test.ts` (the current, non-deprecated
 * strategy-based flow): the client authenticates as the end user via
 * `OidcFederationStrategy` and binds the key to the `sub` claim with a plain
 * `.withLockContext({ identityClaim })`.
 *
 * Gated twice: `describeLivePg` (needs `DATABASE_URL` + CS creds) and an inner
 * `USER_JWT` guard (soft-skip, matching the existing identity/lock-context
 * suites). Whether the searchable index terms are themselves identity-bound is
 * decided inside `@cipherstash/protect-ffi`, not this repo — so we assert the
 * SYMMETRIC behaviour (same lock context on seed + query matches and decrypts),
 * not a cross-identity non-match.
 */
import 'dotenv/config'
import { OidcFederationStrategy } from '@cipherstash/auth'
import { and, asc as drizzleAsc, eq as drizzleEq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, expect, it } from 'vitest'
import { EncryptionV3 } from '@/encryption/v3'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from '@/eql/v3/drizzle'
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'
import { installEqlV3IfNeeded } from '../helpers/eql-v3'
import { describeLivePg, LIVE_EQL_V3_PG_ENABLED } from '../helpers/live-gate'
import { V3_MATRIX } from '../v3-matrix/catalog'

const url = process.env.DATABASE_URL
const sqlClient = LIVE_EQL_V3_PG_ENABLED
  ? postgres(url as string, { prepare: false })
  : (undefined as unknown as postgres.Sql)

const TABLE_NAME = 'protect_ci_v3_drizzle_lock_context'
const RUN = `run-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
const ROW_A = 'row-a'
const ROW_B = 'row-b'
const SECRET_A = 'ada@example.com'
const SECRET_B = 'grace@example.com'

// A fixed identity claim; the same value must be supplied on encrypt and query
// for the terms/keys to reproduce.
const IDENTITY_CLAIM = { identityClaim: ['sub'] }

const secretTable = pgTable(TABLE_NAME, {
  id: integer('id').primaryKey().generatedAlwaysAsIdentity(),
  rowKey: text('row_key').notNull(),
  testRunId: text('test_run_id').notNull(),
  secret: makeEqlV3Column(V3_MATRIX['public.text_eq'].builder('secret')),
} as never)

const schema = extractEncryptionSchemaV3(secretTable)

type SelectRow = { rowKey: string }

let client: Awaited<ReturnType<typeof EncryptionV3>>
let ops: ReturnType<typeof createEncryptionOperatorsV3>
let db: ReturnType<typeof drizzle>
let userJwt: string | undefined

function unwrap<T>(result: { data?: T; failure?: { message: string } }): T {
  if (result.failure) throw new Error(result.failure.message)
  return result.data as T
}

/** Run-scoped SELECT of row keys under an already-encrypted SQL condition. */
async function selectRowKeys(condition: SQL): Promise<string[]> {
  const rows = (await db
    .select({ rowKey: secretTable.rowKey })
    .from(secretTable)
    .where(and(drizzleEq(secretTable.testRunId, RUN), condition))
    .orderBy(drizzleAsc(secretTable.rowKey))) as SelectRow[]
  return rows.map((row) => row.rowKey)
}

beforeAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  userJwt = process.env.USER_JWT
  if (!userJwt) return

  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn)
    throw new Error('CS_WORKSPACE_CRN must be set for lock-context tests')

  await installEqlV3IfNeeded(sqlClient)
  client = await EncryptionV3({
    schemas: [schema],
    config: {
      strategy: OidcFederationStrategy.create(crn, () =>
        Promise.resolve(userJwt as string),
      ),
    },
  })
  ops = createEncryptionOperatorsV3(client)
  db = drizzle({ client: sqlClient })

  await sqlClient.unsafe(`
    CREATE TABLE IF NOT EXISTS ${TABLE_NAME} (
      id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
      row_key TEXT NOT NULL,
      test_run_id TEXT NOT NULL,
      secret public.text_eq NOT NULL
    )
  `)

  // Seed BOTH rows bound to the same lock context.
  const encryptedRows = unwrap<Array<Record<string, unknown>>>(
    await client
      .bulkEncryptModels(
        [
          { rowKey: ROW_A, testRunId: RUN, secret: SECRET_A },
          { rowKey: ROW_B, testRunId: RUN, secret: SECRET_B },
        ] as never,
        schema,
      )
      .withLockContext(IDENTITY_CLAIM),
  )
  await db.insert(secretTable).values(encryptedRows as never)
}, 120000)

afterAll(async () => {
  if (!LIVE_EQL_V3_PG_ENABLED) return
  if (userJwt) {
    await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  }
  await sqlClient.end()
}, 30000)

describeLivePg('v3 drizzle operators with lock context (live pg)', () => {
  const skipUnlessJwt = (): boolean => {
    if (!userJwt) {
      console.log('Skipping lock-context operator test - no USER_JWT provided')
      return true
    }
    return false
  }

  it('eq with a matching lock context selects the exact row', async () => {
    if (skipUnlessJwt()) return
    const condition = await ops.eq(secretTable.secret, SECRET_A, {
      // Runtime accepts a plain { identityClaim } (forwarded to
      // withLockContext); the operator opts type is narrowed to LockContext.
      lockContext: IDENTITY_CLAIM as never,
    })
    expect(await selectRowKeys(condition)).toEqual([ROW_A])
  }, 30000)

  it('a lock-context-bound row decrypts with the same lock context', async () => {
    if (skipUnlessJwt()) return
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT secret::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )
    const decrypted = unwrap(
      await client.decrypt(row.value as never).withLockContext(IDENTITY_CLAIM),
    )
    expect(decrypted).toBe(SECRET_A)
  }, 30000)

  it('eq threads an audit config alongside the lock context', async () => {
    if (skipUnlessJwt()) return
    const condition = await ops.eq(secretTable.secret, SECRET_B, {
      lockContext: IDENTITY_CLAIM as never,
      audit: { metadata: { sub: 'toby@cipherstash.com', type: 'query' } },
    })
    expect(await selectRowKeys(condition)).toEqual([ROW_B])
  }, 30000)
})
