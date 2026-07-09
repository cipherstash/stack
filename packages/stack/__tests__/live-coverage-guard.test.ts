/**
 * Live-coverage guard — a meta-test that is DELIBERATELY NOT wrapped in any
 * `describeLive*` gate, so it always runs (in CI and locally).
 *
 * ## Why this exists
 * Every live (network/DB-touching) suite gates itself on the flags exported by
 * `./helpers/live-gate`:
 *   - `LIVE_CIPHERSTASH_ENABLED`  — all four CS_* creds present
 *   - `LIVE_EQL_V3_PG_ENABLED`    — the above AND `DATABASE_URL` present
 * When a flag is false the suite becomes `describe.skip`. That is correct
 * locally, but in CI it means a rotated/cleared secret (or a missing
 * `DATABASE_URL`) makes the ENTIRE live matrix silently skip while the job
 * still goes GREEN — zero live coverage, no signal.
 *
 * The `require-cs-secrets` CI action catches missing CS_* secrets, but it
 * (a) does NOT check `DATABASE_URL` (the pg-gate input), and (b) only proves
 * the ENV is set on the runner, not that the suites actually consumed it and
 * ran. This meta-test closes both gaps by asserting the very flags the live
 * suites branch on. Because the suites gate on these EXACT flags, proving the
 * flags are `true` in CI transitively guarantees the live suites — and their
 * `beforeAll` setup — execute rather than skip. A silent whole-matrix skip
 * becomes a loud, single-line failure.
 *
 * ## CI-only enforcement
 * Enforcement is scoped to `process.env.CI` (GitHub Actions always sets
 * `CI=true`). Locally, with no creds, this test is a no-op so ordinary dev
 * runs still pass. See `.github/workflows/tests.yml` — the `run-tests` job runs
 * `pnpm run test` on a runner where GitHub injects `CI=true`, and the CS_*
 * creds + `DATABASE_URL` are written into `packages/stack/.env` (loaded here
 * via `dotenv/config`, exactly as the live suites load them).
 *
 * ## Import order matters
 * `import 'dotenv/config'` MUST come first: in CI the creds live in
 * `packages/stack/.env`, and `live-gate` evaluates the flags at module-load
 * time. Loading dotenv before importing the gate mirrors what every live suite
 * does and ensures the flags reflect the real environment.
 *
 * ## Layer 2 (execution census) — intentionally NOT added
 * A stronger check would assert each critical live file executed its expected
 * number of tests with zero skips (e.g. via `--reporter=json` + a script, or a
 * vitest `onFinished` hook). It is omitted on purpose:
 *   - The live suites gate on the SAME flags asserted here, so this Layer-1
 *     check already guarantees they run — a census would only re-detect the
 *     same "did the matrix run" failure it is meant to catch.
 *   - A per-file count census needs hardcoded expected totals that drift every
 *     time a domain/case is added, turning a safety net into maintenance debt.
 *   - It would add an extra CI step / reporter wiring for marginal signal.
 * If a future regression is ever a *partial* skip (individual `it.skip` inside
 * an enabled suite — a different failure mode than the silent whole-matrix skip
 * this guards), extend here with a `--reporter=json` post-run script asserting
 * `numPendingTests === 0` for the critical files, rather than hardcoding counts.
 */
import 'dotenv/config'
import { describe, expect, it } from 'vitest'
import {
  LIVE_CIPHERSTASH_ENABLED,
  LIVE_EQL_V3_PG_ENABLED,
  LIVE_LOCK_CONTEXT_ENABLED,
  LIVE_PG_ENABLED,
  LIVE_SUPABASE_PGREST_ENABLED,
} from './helpers/live-gate'

// GitHub Actions always sets CI=true; treat any truthy CI as "must run live".
const IN_CI = Boolean(process.env.CI)

describe('live-coverage guard', () => {
  it.runIf(IN_CI)(
    'CI must have CipherStash creds so the live suites do not silently skip',
    () => {
      expect(
        LIVE_CIPHERSTASH_ENABLED,
        'CI must run the live suites — CS_* creds missing (CS_WORKSPACE_CRN / ' +
          'CS_CLIENT_ID / CS_CLIENT_KEY / CS_CLIENT_ACCESS_KEY) → every ' +
          '`describeLive` suite becomes describe.skip and the live matrix ' +
          'silently skips while CI stays green.',
      ).toBe(true)
    },
  )

  it.runIf(IN_CI)(
    'CI must have DATABASE_URL so the live pg suites do not silently skip',
    () => {
      expect(
        LIVE_EQL_V3_PG_ENABLED,
        'CI must run the live Postgres suites — `LIVE_EQL_V3_PG_ENABLED` is ' +
          'false. This needs the CS_* creds AND a `DATABASE_URL`; a missing ' +
          'DATABASE_URL is the hole the require-cs-secrets action does not ' +
          'cover, and makes every `describeLivePg` suite silently skip.',
      ).toBe(true)
    },
  )

  // DEFERRED (follow-up): the CI `USER_JWT` secret is not yet provisioned, so
  // enforcing this now would fail CI. Skipped until the secret exists — flip
  // back to `it.runIf(IN_CI)` at that point. It still documents the real gap:
  // the identity / lock-context live suites soft-skip on a missing USER_JWT, so
  // once the secret lands this guard turns a silent whole-suite skip into a
  // loud failure (as the CS_*/DATABASE_URL guards already do).
  it.skip('CI must have USER_JWT so the lock-context live suites do not silently skip', () => {
    expect(
      LIVE_LOCK_CONTEXT_ENABLED,
      'CI must run the live lock-context / identity suites — ' +
        '`LIVE_LOCK_CONTEXT_ENABLED` is false. This needs the CS_* creds AND ' +
        'a `USER_JWT`; the identity/lock-context suites (e.g. ' +
        'lock-context.test.ts, protect-ops.test.ts, ' +
        'operators-lock-context-live-pg.test.ts) SOFT-SKIP when USER_JWT is ' +
        'absent, so a missing/rotated USER_JWT lets them skip green with no ' +
        'signal — the exact failure mode this guard exists to prevent.',
    ).toBe(true)
  })

  it.runIf(IN_CI)(
    'CI must have DATABASE_URL so the pg-only suites do not silently skip',
    () => {
      expect(
        LIVE_PG_ENABLED,
        'CI must run the DB-only suites — `LIVE_PG_ENABLED` is false. This ' +
          'needs only `DATABASE_URL` (no CS_* creds: introspection reads the ' +
          'schema, it does not encrypt), and `.github/workflows/tests.yml` ' +
          'writes it as a literal into packages/stack/.env alongside a Postgres ' +
          'service — so a false value here is a broken workflow, never a valid ' +
          'configuration. It makes every `describeLivePgOnly` suite (e.g. ' +
          'supabase-v3-introspect-pg) silently skip while CI stays green.',
      ).toBe(true)
    },
  )

  it.runIf(IN_CI)(
    'CI must have PGRST_URL so the live supabase PostgREST suite does not silently skip',
    () => {
      expect(
        LIVE_SUPABASE_PGREST_ENABLED,
        'CI must run the live supabase PostgREST suite — ' +
          '`LIVE_SUPABASE_PGREST_ENABLED` is false. This needs a ' +
          '`DATABASE_URL` AND a `PGRST_URL` pointing at the pinned ' +
          '`postgrest/postgrest` service in .github/workflows/tests.yml (no ' +
          'CS_* creds — the domain CHECKs are structural). It is ' +
          'the ONLY suite that executes the adapter against a real PostgREST — ' +
          'the `prop:db_name::jsonb` aliasing selects, the `cs` containment ' +
          'mapping, and the full-envelope filter operands that every `public.*` ' +
          'domain CHECK must accept. Everything else asserts those as strings ' +
          'against a mock, so a false value here means the wire encoding is ' +
          'unproven while CI stays green.',
      ).toBe(true)
    },
  )

  // Local dev with no creds: nothing to assert. Keep at least one always-run
  // assertion so the file is never reported as fully empty/pending.
  it('is always collected (guard file runs outside every live gate)', () => {
    expect(typeof IN_CI).toBe('boolean')
  })
})
