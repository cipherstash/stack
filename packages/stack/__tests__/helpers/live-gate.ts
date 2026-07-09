import { describe } from 'vitest'

/**
 * Shared env gates for the live (network-touching) suites. Previously each
 * live suite re-declared these; one definition keeps the credential list —
 * and therefore what "live" means — from drifting between files.
 *
 * Callers must `import 'dotenv/config'` BEFORE importing this module (all
 * live suites already do, as their first import) so the env is populated
 * when these are evaluated.
 */

/** True when live CipherStash (ZeroKMS/CTS) credentials are configured. */
export const LIVE_CIPHERSTASH_ENABLED = Boolean(
  process.env.CS_WORKSPACE_CRN &&
    process.env.CS_CLIENT_ID &&
    process.env.CS_CLIENT_KEY &&
    process.env.CS_CLIENT_ACCESS_KEY,
)

/** True when live credentials AND a Postgres `DATABASE_URL` are configured. */
export const LIVE_EQL_V3_PG_ENABLED = Boolean(
  process.env.DATABASE_URL && LIVE_CIPHERSTASH_ENABLED,
)

/**
 * True when live credentials AND a `USER_JWT` are configured. The identity /
 * lock-context live suites additionally require a `USER_JWT` to bind keys to an
 * end-user identity, and SOFT-SKIP (inline `if (!userJwt) return`) when it is
 * absent — so a missing/rotated `USER_JWT` lets them skip green in CI. This
 * flag lets the live-coverage guard assert that path is actually exercised.
 */
export const LIVE_LOCK_CONTEXT_ENABLED = Boolean(
  process.env.USER_JWT && LIVE_CIPHERSTASH_ENABLED,
)

export const describeLive = LIVE_CIPHERSTASH_ENABLED ? describe : describe.skip

export const describeLivePg = LIVE_EQL_V3_PG_ENABLED ? describe : describe.skip

/**
 * True when only a Postgres `DATABASE_URL` is configured (no CipherStash creds
 * needed — introspection reads the schema, it does not encrypt).
 *
 * Like the flags above, a false value turns its suites into `describe.skip`,
 * which in CI would be a silent whole-suite skip on a green job. That hole is
 * closed by `../live-coverage-guard.test.ts`, which asserts THIS flag in CI.
 * Any new gate flag added here must be asserted there too.
 */
export const LIVE_PG_ENABLED = Boolean(process.env.DATABASE_URL)

export const describeLivePgOnly = LIVE_PG_ENABLED ? describe : describe.skip

/**
 * True when a real PostgREST is reachable AND a `DATABASE_URL` is configured.
 *
 * The supabase v3 adapter talks to PostgREST, not to Postgres — the aliasing
 * `prop:db_name::jsonb` casts, the `cs` containment mapping, the quoted
 * envelopes inside `or=(…)`, and the full storage envelope every `public.*`
 * domain CHECK must accept are all things only a real server can execute.
 * Everything else in the repo asserts them as strings against a mock.
 *
 * NO CipherStash creds: the suite builds structurally-valid envelopes itself
 * (the domain CHECKs are structural — `v`/`i`/`c` plus the domain's index
 * terms), so it can run wherever the DB-only suites run. It proves the WIRE and
 * the GRANTS. Cryptographic round-tripping is `drizzle-v3/operators-live-pg`'s
 * job and needs the credentials.
 */
export const LIVE_SUPABASE_PGREST_ENABLED =
  Boolean(process.env.PGRST_URL) && LIVE_PG_ENABLED

export const describeLiveSupabasePgrest = LIVE_SUPABASE_PGREST_ENABLED
  ? describe
  : describe.skip
