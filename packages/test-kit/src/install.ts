import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)

/** `packages/test-kit/src` → repo root. */
const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..')
const STASH_BIN = resolve(REPO_ROOT, 'packages/cli/dist/bin/stash.js')

export type DbVariant = 'postgres' | 'supabase'

/**
 * Which database the integration suite is pointed at.
 *
 * Set `CS_IT_DB_VARIANT` explicitly. The `PGRST_URL` fallback exists only for a
 * developer running one suite by hand, and it is a guess: it once inferred
 * `postgres` for the Drizzle job running against `supabase/postgres`, because
 * that job needs no PostgREST and leaves the variable unset. The consequence was
 * silent — EQL installed without `--supabase`, so the role grants were never
 * applied and the grants test skipped, while the suite passed because Drizzle
 * connects as `postgres` rather than as `anon`.
 *
 * The variant decides how EQL is installed. It must not be a guess in CI.
 */
export function dbVariant(): DbVariant {
  const explicit = process.env['CS_IT_DB_VARIANT']
  if (explicit === 'postgres' || explicit === 'supabase') return explicit
  return process.env['PGRST_URL'] ? 'supabase' : 'postgres'
}

/**
 * Install EQL v3 by running the real `stash eql install`, not by applying the
 * SQL bundle directly.
 *
 * The installer is a shipped product surface — it vendors the bundle, verifies
 * it against the release manifest, decides what to skip on a non-superuser, and
 * applies the Supabase role grants. Driving it here means an installer
 * regression fails the integration jobs instead of hiding behind a test-only
 * code path that reimplements half of it.
 *
 * Notes on the flags:
 * - `--supabase` applies the `eql_v3` AND `eql_v3_internal` grants to
 *   anon/authenticated/service_role. The SECURITY INVOKER extractors need both.
 * - `--direct` is required alongside it: `--supabase` alone prompts for an
 *   install mode (migration vs direct) and would hang a CI job.
 * - Verified against `supabase/postgres:17.4.1.048` as the NON-superuser
 *   `postgres` role: no superuser connection is needed.
 */
export async function installEqlV3(
  databaseUrl: string,
  variant: DbVariant = dbVariant(),
): Promise<void> {
  if (!existsSync(STASH_BIN)) {
    throw new Error(
      `The stash CLI is not built (${STASH_BIN} is missing).\n` +
        'The integration suites install EQL v3 through the real CLI. Build it first:\n' +
        '  pnpm exec turbo run build --filter stash',
    )
  }

  const args = ['eql', 'install', '--eql-version', '3']
  if (variant === 'supabase') args.push('--supabase', '--direct')
  args.push('--database-url', databaseUrl)

  try {
    await execFileAsync(process.execPath, [STASH_BIN, ...args], {
      cwd: REPO_ROOT,
      // The CLI is a clack TUI. Without a TTY it takes its non-interactive
      // paths, which is what we want; `CI` makes that explicit.
      env: { ...process.env, CI: '1' },
      maxBuffer: 32 * 1024 * 1024,
    })
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause)
    throw new Error(
      `stash eql install --eql-version 3${variant === 'supabase' ? ' --supabase --direct' : ''} failed.\n` +
        'This is the real installer, so a failure here is a real bug — do not work around it.\n' +
        detail,
    )
  }
}
