import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import { sharedAlias, stackSourceAlias } from '../../../vitest.shared'
import {
  integrationHarness,
  integrationTestDefaults,
} from '../../test-kit/src/integration/config'

/**
 * Integration suites: real ZeroKMS, real Postgres, real PostgREST.
 *
 * Deliberately a SEPARATE config from `packages/stack/vitest.config.ts`, which
 * excludes `integration/**`. `pnpm test` must stay runnable with no credentials
 * and no database; these run only under `test:integration:*`, from their own CI
 * jobs. That separation is what lets the integration suites throw on missing
 * configuration instead of skipping.
 *
 * `CS_IT_SUITE` selects which suites run, so one config serves every adapter
 * without a second near-identical file. Comma-separated globs; each CI job scopes
 * itself to the adapter it provisioned a database for. Locally it defaults to
 * everything.
 *
 * Scoping matters: the Drizzle suites talk straight to Postgres and the Supabase
 * suites need PostgREST, so a job running both would have to provision both.
 */
const ROOT = resolve(__dirname, '..')

const SUITE_GLOBS = (
  process.env['CS_IT_SUITE'] ?? 'integration/**/*.integration.test.ts'
)
  .split(',')
  .map((glob) => glob.trim())
  .filter(Boolean)

/**
 * Guard against a glob that resolves to nothing — the silent-zero-coverage hole
 * the deleted `live-coverage-guard.test.ts` used to backstop. A directory
 * renamed/moved (or a typo) while the workflow's `CS_IT_SUITE` still points at
 * the old path makes vitest collect the OTHER globs, pass, and drop those suites
 * with no signal — `passWithNoTests` only catches the all-empty case, and the
 * no-skips reporter only sees files that were collected.
 *
 * The literal directory prefix of each glob (everything before the first glob
 * metacharacter) must exist. This catches the whole-directory rename directly;
 * `passWithNoTests: false` (below) still covers a fully-empty run.
 */
for (const glob of SUITE_GLOBS) {
  const literalPrefix = glob
    .split('/')
    .slice(
      0,
      glob.split('/').findIndex((seg) => /[*?{}[\]]/.test(seg)),
    )
    .join('/')
  // No metacharacter at all → the glob is a literal file path; check it whole.
  const target = /[*?{}[\]]/.test(glob) ? literalPrefix : glob
  if (target && !existsSync(resolve(ROOT, target))) {
    throw new Error(
      `CS_IT_SUITE glob "${glob}" points at "${target}", which does not exist. ` +
        'A renamed/moved integration directory would otherwise drop its suites ' +
        'from CI silently. Fix the glob (or the directory) so the suites run.',
    )
  }
}

export default defineConfig({
  resolve: { alias: { ...sharedAlias, ...stackSourceAlias } },
  test: {
    root: resolve(__dirname, '..'),
    // Unlike the adapter packages (fixed glob), stack's integration job scopes to
    // its shared/ + identity/ suites via CS_IT_SUITE — hence the guard above.
    include: SUITE_GLOBS,
    ...integrationHarness,
    ...integrationTestDefaults,
  },
})
