import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { defineConfig } from 'vitest/config'
import { sharedAlias } from '../../../vitest.shared'

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
  resolve: {
    alias: {
      ...sharedAlias,
      '@/': resolve(__dirname, '../src') + '/',
      '@cipherstash/protect-ffi/wasm-inline': resolve(
        __dirname,
        '../__tests__/helpers/stub-protect-ffi-wasm-inline.ts',
      ),
      '@cipherstash/auth/wasm-inline': resolve(
        __dirname,
        '../__tests__/helpers/stub-auth-wasm-inline.ts',
      ),
    },
  },
  test: {
    root: resolve(__dirname, '..'),
    include: SUITE_GLOBS,
    globalSetup: [resolve(__dirname, 'global-setup.ts')],
    server: {
      deps: {
        // `@cipherstash/test-kit` resolves to source in ANOTHER package, i.e.
        // outside this config's root, so Vitest externalizes it and loads it
        // through Node rather than the transform pipeline. Its driver imports
        // `vitest`, and a `vitest` imported outside a worker cannot reach the
        // runner's state: "Vitest failed to access its internal state".
        inline: [/packages\/test-kit/],
      },
    },
    // Real crypto round-trips over the network. The unit config uses 30s for the
    // same reason; seeding a family table encrypts every sample, so hooks need
    // more headroom than tests do.
    testTimeout: 60_000,
    hookTimeout: 180_000,
    // One database, shared tables. File-level parallelism would have two family
    // suites installing EQL and reloading the PostgREST schema cache at once.
    fileParallelism: false,

    /**
     * Show console output only for tests that FAIL.
     *
     * The capability-rejection tests are the bulk of the suite, and each one
     * makes the adapter refuse an operation. `EncryptedQueryBuilderImpl.execute`
     * logs `logger.error(...)` before returning its `Result` error, so every
     * passing rejection emits an ERROR block with a stack trace. A CI run
     * printed 213 of them — all from passing tests — which is enough noise to
     * bury a real failure and enough to make a green job look broken.
     *
     * `'passed-only'` suppresses those and keeps the logs of any test that
     * actually fails, which is when they are worth reading. The stack logger has
     * no silent level (`STASH_STACK_LOG` bottoms out at `error`), so this is the
     * only place to do it without changing product logging behaviour.
     */
    silent: 'passed-only',

    // A fully-empty run is a failure, not a pass: paired with the per-glob
    // directory guard above, a mistyped/renamed suite path can never go green.
    passWithNoTests: false,

    // Fail the run if anything is skipped. A skipped test reads exactly like a
    // passing one, and every silent hole this suite has found took that shape.
    reporters: ['default', resolve(__dirname, 'no-skips-reporter.ts')],
  },
})
