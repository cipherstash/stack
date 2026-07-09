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
