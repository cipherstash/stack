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
 * Lives under `integration/identity/`: like every integration suite it THROWS
 * rather than skips when unconfigured, and additionally requires `USER_JWT`
 * (asserted in `beforeAll` via `requireIntegrationEnv(['userjwt'])`). That
 * directory is not yet in any CI job's suite globs — the `USER_JWT` repo secret
 * is unprovisioned (#530) — so these run locally with a token today and join CI
 * once the secret lands. Whether the searchable index terms are themselves
 * identity-bound is decided inside `@cipherstash/protect-ffi`, not this repo.
 *
 * We assert the symmetric behaviour (same lock context on seed + query matches
 * and decrypts) AND the negative path — an identity-bound row must not match a
 * query issued with no lock context, and must not decrypt without it. The
 * symmetric tests alone are insufficient: they drop the context identically on
 * both sides, so they stay green even if it were ignored entirely.
 *
 * A cross-identity non-match (sealed under A, queried under B) still needs a
 * second JWT with a different `sub` — a lock context only names the claim while
 * ZeroKMS resolves its value from the authenticating token. Tracked separately.
 */
import { OidcFederationStrategy } from '@cipherstash/auth'
import {
  databaseUrl,
  requireIntegrationEnv,
  V3_MATRIX,
} from '@cipherstash/test-kit'
import { and, asc as drizzleAsc, eq as drizzleEq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { EncryptionV3 } from '@/encryption/v3'
import {
  createEncryptionOperatorsV3,
  extractEncryptionSchemaV3,
} from '@/eql/v3/drizzle'
import { makeEqlV3Column } from '@/eql/v3/drizzle/column'

const sqlClient = postgres(databaseUrl(), { prepare: false })

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
  secret: makeEqlV3Column(V3_MATRIX['public.eql_v3_text_eq'].builder('secret')),
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

/**
 * The outcome of a decrypt attempt that is EXPECTED to be denied. `decrypt`
 * reports denial as a `Result.failure` rather than throwing, so a bare `await`
 * would resolve and a naive `expect(...).rejects` would never fire — denial has
 * to be read off the result. A throw also counts as denial.
 *
 * Returns the message, not just a boolean, so callers can assert WHY it was
 * denied. A bare boolean would let any infrastructure fault — a DNS failure, an
 * expired CTS token, a ZeroKMS outage ("SendRequest: Failed to send request") —
 * read as "the identity boundary held", and the security test would pass for
 * the wrong reason.
 */
async function decryptOutcome(
  attempt: () => PromiseLike<{ failure?: { message: string } }>,
): Promise<{ denied: boolean; message: string }> {
  try {
    const result = await attempt()
    return {
      denied: Boolean(result.failure),
      message: result.failure?.message ?? '',
    }
  } catch (error) {
    return { denied: true, message: (error as Error).message }
  }
}

/**
 * A genuine key-derivation denial. ZeroKMS cannot reproduce the key tag without
 * the identity claim the row was sealed under, and says so. Asserted verbatim
 * elsewhere in the suite (`lock-context.test.ts`, `protect-ops.test.ts`).
 */
const KEY_DENIAL = /^Failed to retrieve key/

/**
 * Denial under a claim the token may not carry at all. Naming a claim does not
 * assert it exists: `resolveLockContext` is a passthrough, and ZeroKMS resolves
 * the claim's value from the authenticating token. So decrypting under
 * `['email']` a row sealed under `['sub']` either fails key derivation, or — if
 * the token has no `email` claim — is refused by the authorization layer before
 * key derivation is ever attempted. Both are denials; which one surfaces is a
 * ZeroKMS server-side detail we do not pin.
 *
 * What must NOT pass is an infrastructure fault masquerading as a denial, so
 * that is excluded separately. Kept loose rather than pinned to `KEY_DENIAL`
 * because no CI run exercises this path — `USER_JWT` is unset in CI (#530) —
 * and a wrong message-shape guess would only surface once that secret lands.
 */
const IDENTITY_DENIAL =
  /failed to retrieve key|unauthoriz|unauthoris|forbidden|denied|not authorized|not authorised/i

/** A transport/outage failure, which must never be mistaken for a denial. */
const INFRA_FAULT =
  /ECONNREFUSED|ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|timed? ?out|network error/i

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
  requireIntegrationEnv(['userjwt'])
  userJwt = process.env.USER_JWT as string

  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn)
    throw new Error('CS_WORKSPACE_CRN must be set for lock-context tests')

  // EQL v3 is installed once per run by `global-setup.ts`.
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
      secret public.eql_v3_text_eq NOT NULL
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
  await sqlClient`DELETE FROM ${sqlClient(TABLE_NAME)} WHERE test_run_id = ${RUN}`
  await sqlClient.end()
}, 30000)

describe('v3 drizzle operators with lock context (live pg)', () => {
  it('eq with a matching lock context selects the exact row', async () => {
    const condition = await ops.eq(secretTable.secret, SECRET_A, {
      // Runtime accepts a plain { identityClaim } (forwarded to
      // withLockContext); the operator opts type is narrowed to LockContext.
      lockContext: IDENTITY_CLAIM as never,
    })
    expect(await selectRowKeys(condition)).toEqual([ROW_A])
  }, 30000)

  it('a lock-context-bound row decrypts with the same lock context', async () => {
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT secret::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )
    expect(row).toBeDefined()

    const decrypted = unwrap(
      await client.decrypt(row.value as never).withLockContext(IDENTITY_CLAIM),
    )
    expect(decrypted).toBe(SECRET_A)
  }, 30000)

  it('eq threads an audit config alongside the lock context', async () => {
    const condition = await ops.eq(secretTable.secret, SECRET_B, {
      lockContext: IDENTITY_CLAIM as never,
      audit: { metadata: { sub: 'toby@cipherstash.com', type: 'query' } },
    })
    expect(await selectRowKeys(condition)).toEqual([ROW_B])
  }, 30000)

  // NEGATIVE PATH. The three tests above all supply the SAME lock context on
  // seed and on query, so they cannot distinguish "lock context applied" from
  // "lock context silently ignored": a regression that dropped the context from
  // the index term would drop it identically on both sides and still match.
  // These assert that an identity-bound row is NOT reachable without its
  // context — the property the suite exists to protect.
  //
  // A true CROSS-identity proof (sealed under A, queried under B) needs a
  // second JWT with a different `sub`; the lock context only names the claim
  // (`['sub']`) while ZeroKMS resolves its value from the authenticating token.
  // No `USER_JWT_B` exists, so that remains a follow-up.
  it('an identity-bound row does not match an eq issued with no lock context', async () => {
    // The control, in this test rather than a sibling one. `[]` is what a held
    // identity boundary and an unseeded fixture both look like, so the empty
    // assertion below proves nothing on its own — it only means something
    // against a demonstration that the row IS reachable with the context.
    const bound = await ops.eq(secretTable.secret, SECRET_A, {
      lockContext: IDENTITY_CLAIM as never,
    })
    expect(await selectRowKeys(bound)).toEqual([ROW_A])

    const unbound = await ops.eq(secretTable.secret, SECRET_A)
    expect(await selectRowKeys(unbound)).toEqual([])
  }, 30000)

  it('an identity-bound row does not decrypt without its lock context', async () => {
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT secret::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )

    // A missing fixture would make `row.value` throw a TypeError inside
    // `decryptOutcome`, which counts a throw as denial. The message assertions
    // below already reject that string, so the test fails either way — but it
    // fails blaming the denial regex. Name the real fault here instead.
    expect(row).toBeDefined()

    // `decrypt` reports denial as a `Result.failure` and does not throw, so a
    // bare `await` here would silently pass. Require denial via either channel,
    // AND require it be a key-derivation denial rather than an outage.
    const { denied, message } = await decryptOutcome(() =>
      client.decrypt(row.value as never),
    )

    expect(denied).toBe(true)
    expect(message).toMatch(KEY_DENIAL)
  }, 30000)

  it('an identity-bound row does not decrypt under a different identity claim', async () => {
    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT secret::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )

    expect(row).toBeDefined()

    const { denied, message } = await decryptOutcome(() =>
      client
        .decrypt(row.value as never)
        .withLockContext({ identityClaim: ['email'] } as never),
    )

    expect(denied).toBe(true)
    expect(message).toMatch(IDENTITY_DENIAL)
    expect(message).not.toMatch(INFRA_FAULT)
  }, 30000)
})
