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
 * The client authenticates via `OidcFederationStrategy`, federating a
 * freshly-minted Clerk M2M JWT (`clerkJwtProvider()`) into a CTS token, and
 * binds the key to the `sub` claim — resolved by ZeroKMS from the token, here
 * the Clerk machine identity — with a plain `.withLockContext({ identityClaim })`.
 *
 * Lives under `integration/identity/`: like every integration suite it THROWS
 * rather than skips when unconfigured (`clerkJwtProvider()` asserts
 * `CLERK_MACHINE_TOKEN`). Whether the searchable index terms are themselves
 * identity-bound is decided inside `@cipherstash/protect-ffi`, not this repo.
 *
 * We assert the symmetric behaviour (same lock context on seed + query matches
 * and decrypts) AND the negative path. The boundary is at DECRYPTION: an
 * identity-bound row must not decrypt without its context. Search is NOT the
 * boundary — the equality term is workspace-scoped, so a no-context query still
 * matches (see the negative-path tests). The symmetric tests alone are
 * insufficient: they drop the context identically on both sides, so they stay
 * green even if it were ignored entirely.
 *
 * The cross-identity non-match (sealed under A, decrypted under B) is covered by
 * the final test: it federates a SECOND Clerk machine (`CLERK_MACHINE_TOKEN_B`,
 * a distinct `sub`) and asserts B cannot read A's row, with A reading it as the
 * control.
 */
import { OidcFederationStrategy } from '@cipherstash/stack'
import { EncryptionV3 } from '@cipherstash/stack/v3'
import { databaseUrl, unwrapResult, V3_MATRIX } from '@cipherstash/test-kit'
import { clerkJwtProvider } from '@cipherstash/test-kit/integration-clerk'
import { and, asc as drizzleAsc, eq as drizzleEq, type SQL } from 'drizzle-orm'
import { integer, pgTable, text } from 'drizzle-orm/pg-core'
import { drizzle } from 'drizzle-orm/postgres-js'
import postgres from 'postgres'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { makeEqlV3Column } from '../src/column'
import {
  createEncryptionOperators,
  extractEncryptionSchema,
} from '../src/index.js'

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

const schema = extractEncryptionSchema(secretTable)

type SelectRow = { rowKey: string }

let client: Awaited<ReturnType<typeof EncryptionV3>>
let ops: ReturnType<typeof createEncryptionOperators>
let db: ReturnType<typeof drizzle>

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
 * because which of the two denials surfaces is a ZeroKMS server-side detail,
 * and the Clerk machine token may or may not carry an `email` claim.
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
  const crn = process.env.CS_WORKSPACE_CRN
  if (!crn)
    throw new Error('CS_WORKSPACE_CRN must be set for lock-context tests')

  // A freshly-minted Clerk M2M JWT federates into a CTS token; the strategy
  // re-mints via this callback on expiry. `clerkJwtProvider()` asserts
  // CLERK_MACHINE_TOKEN (throws if absent). EQL v3 is installed once per run by
  // `global-setup.ts`.
  //
  // `create()` returns a `Result` — unwrap to the strategy itself, which is what
  // `config.authStrategy` expects (it calls `.getToken()` on it).
  const federation = OidcFederationStrategy.create(crn, clerkJwtProvider())
  if (federation.failure) {
    throw new Error(`[federation]: ${federation.failure.message}`)
  }
  client = await EncryptionV3({
    schemas: [schema],
    config: { authStrategy: federation.data },
  })
  ops = createEncryptionOperators(client)
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
  const encryptedRows = unwrapResult<Array<Record<string, unknown>>>(
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

    const decrypted = unwrapResult(
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

  // NEGATIVE PATH. The identity boundary is enforced at DECRYPTION, not at
  // search. The equality term (`hm`/`eq_term` HMAC) is workspace-scoped: a query
  // WITHOUT the lock context produces the same term and matches the same row —
  // but the value still cannot be decrypted without the context (second test
  // below). To run the no-context query at all you must already know the
  // plaintext to build the term, and you can confirm a match but never read the
  // row.
  //
  // Whether search terms SHOULD be identity-bound is a CipherStash design
  // question, raised with the team. An earlier version of the first test
  // assumed they were and asserted `[]`; this is corrected to the OBSERVED
  // behaviour, with the real boundary proven by the decryption test.
  //
  // The true CROSS-identity proof (sealed under A, decrypted under B) needs a
  // SECOND machine identity with a different `sub`; the lock context only names
  // the claim (`['sub']`) while ZeroKMS resolves its value from the
  // authenticating token. That is the final test in this suite, federating
  // `CLERK_MACHINE_TOKEN_B`.
  it('an eq matches the same row with or without a lock context (search is not identity-bound)', async () => {
    const bound = await ops.eq(secretTable.secret, SECRET_A, {
      lockContext: IDENTITY_CLAIM as never,
    })
    expect(await selectRowKeys(bound)).toEqual([ROW_A])

    // Same HMAC term, no context — still matches. Decryption, not search, is
    // the identity boundary (proven by the next test).
    const unbound = await ops.eq(secretTable.secret, SECRET_A)
    expect(await selectRowKeys(unbound)).toEqual([ROW_A])
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

  // The true cross-identity proof: same `['sub']` claim, a DIFFERENT
  // authenticating machine. Everything above uses one identity, so it cannot
  // tell "bound to A" from "bound to nothing" — this can. Machine B must be a
  // distinct machine (its own `sub`) in the same Clerk instance registered on
  // the workspace; `clerkJwtProvider('CLERK_MACHINE_TOKEN_B')` throws if that
  // token is unset, so this fails loudly rather than skipping.
  it('a row sealed under identity A does not decrypt under a different identity (B)', async () => {
    const crn = process.env.CS_WORKSPACE_CRN as string
    const federationB = OidcFederationStrategy.create(
      crn,
      clerkJwtProvider('CLERK_MACHINE_TOKEN_B'),
    )
    if (federationB.failure) {
      throw new Error(`[federation B]: ${federationB.failure.message}`)
    }
    const clientB = await EncryptionV3({
      schemas: [schema],
      config: { authStrategy: federationB.data },
    })

    const [row] = await sqlClient.unsafe<Array<{ value: unknown }>>(
      `SELECT secret::jsonb AS value FROM ${TABLE_NAME}
         WHERE test_run_id = $1 AND row_key = $2`,
      [RUN, ROW_A],
    )
    expect(row).toBeDefined()

    // Control: identity A reads its own row. If this is denied, A's federation
    // or the fixture is broken and the cross-identity assertion below would
    // "pass" for the wrong reason.
    const asA = await decryptOutcome(() =>
      client.decrypt(row.value as never).withLockContext(IDENTITY_CLAIM),
    )
    expect(
      asA.denied,
      `identity A must read its own row (got: ${asA.message})`,
    ).toBe(false)

    // Cross-identity: B names the same `['sub']` claim, but its value is B's
    // machine, so ZeroKMS derives a DIFFERENT key and refuses — a genuine
    // key-derivation denial (`Failed to retrieve key`). Pin to KEY_DENIAL, NOT
    // the broad IDENTITY_DENIAL: B is a valid, registered machine, so it
    // authenticates fine and the denial must surface at key derivation. Were B
    // instead rejected at the authorization layer (e.g. its machine not
    // registered on the workspace), that "unauthorized" message would satisfy
    // IDENTITY_DENIAL and the test would pass GREEN without ever exercising the
    // identity boundary — proving "B can't authenticate", not "B can't reproduce
    // A's key".
    const asB = await decryptOutcome(() =>
      clientB.decrypt(row.value as never).withLockContext(IDENTITY_CLAIM),
    )
    expect(asB.denied, 'identity B must NOT decrypt a row sealed under A').toBe(
      true,
    )
    expect(asB.message).toMatch(KEY_DENIAL)
    expect(asB.message).not.toMatch(INFRA_FAULT)
  }, 30000)
})
