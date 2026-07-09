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

  // Local dev with no creds: nothing to assert. Keep at least one always-run
  // assertion so the file is never reported as fully empty/pending.
  it('is always collected (guard file runs outside every live gate)', () => {
    expect(typeof IN_CI).toBe('boolean')
  })
})
