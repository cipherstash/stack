/**
 * Self-gating for the live-PG EQL v3 suites.
 *
 * The live suites need two things a hermetic CI job does not have:
 *
 *   1. **CipherStash credentials** for the real ZeroKMS round-trips —
 *      either ALL FOUR `CS_*` variables in the environment, or (locally)
 *      a `~/.cipherstash` device profile written by `stash auth login`,
 *      which protect-ffi's `AutoStrategy` picks up with no environment
 *      at all. A PARTIAL `CS_*` environment counts as neither: it would
 *      fail deep inside the client with "[encryption]: Not
 *      authenticated", which names nothing — mirroring the rejection
 *      rationale in `packages/test-kit/src/env.ts`.
 *   2. **A Postgres to talk to** — `DATABASE_URL`. Locally:
 *
 *        docker compose -f local/docker-compose.postgres.yml up -d --wait
 *        export DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash
 *
 * When either is missing the suites SKIP (describe.skip) so the default
 * `pnpm test` run stays green on machines without secrets — the posture
 * the plan chose for this package (unlike `packages/stack/integration`,
 * whose suites run under a separate config and throw instead).
 */

import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { describe } from 'vitest'

const CS_VARS = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
] as const

const missing = CS_VARS.filter((name) => !process.env[name])
const hasProfile = existsSync(join(homedir(), '.cipherstash'))

export const LIVE_CIPHERSTASH_ENABLED =
  missing.length === 0 || (missing.length === CS_VARS.length && hasProfile)

export const LIVE_EQL_V3_PG_ENABLED = Boolean(
  process.env.DATABASE_URL && LIVE_CIPHERSTASH_ENABLED,
)

export const describeLivePg = LIVE_EQL_V3_PG_ENABLED ? describe : describe.skip

/** The database URL, once the gate has established it exists. */
export function liveDatabaseUrl(): string {
  const url = process.env.DATABASE_URL
  if (!url) {
    throw new Error(
      'liveDatabaseUrl() called while the live gate is closed — guard the suite with describeLivePg.',
    )
  }
  return url
}
