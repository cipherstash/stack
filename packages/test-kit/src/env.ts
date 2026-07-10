import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * Integration suites FAIL when they are not configured. They never skip.
 *
 * The suites they replace were gated by `describe.skipIf(...)`, which turns a
 * missing credential into a silent whole-suite skip on a green job — the exact
 * failure `live-coverage-guard.test.ts` exists to paper over. Throwing removes
 * the need for that guard: an unconfigured run is red, and the message says how
 * to fix it.
 */

export type Requirement = 'cipherstash' | 'database' | 'pgrest'

/**
 * CipherStash credentials resolve from EITHER the four `CS_*` variables OR a
 * local `~/.cipherstash` profile written by `stash auth login`. protect-ffi
 * builds an `AutoStrategy` that consults both, so a developer who has logged in
 * once needs no environment at all; CI, which has no profile, supplies the vars.
 *
 * Mirrors `examples/prisma/test/e2e/global-setup.ts`, which already resolves
 * credentials this way.
 */
function hasCipherStashCredentials(): boolean {
  if (process.env['CS_WORKSPACE_CRN']) return true
  return existsSync(join(homedir(), '.cipherstash'))
}

const HINTS: Record<Requirement, () => string | null> = {
  cipherstash: () =>
    hasCipherStashCredentials()
      ? null
      : 'CipherStash credentials. Either set CS_WORKSPACE_CRN, CS_CLIENT_ID, ' +
        'CS_CLIENT_KEY and CS_CLIENT_ACCESS_KEY, or run `stash auth login` once ' +
        '(writes ~/.cipherstash, which AutoStrategy picks up).',

  database: () =>
    process.env['DATABASE_URL']
      ? null
      : 'DATABASE_URL. Start a database and point at it:\n' +
        '      docker compose -f local/docker-compose.postgres.yml up -d --wait\n' +
        '      export DATABASE_URL=postgres://cipherstash:password@localhost:55432/cipherstash\n' +
        '    ...or, for the Supabase variant:\n' +
        '      docker compose -f local/docker-compose.supabase.yml up -d --wait\n' +
        '      export DATABASE_URL=postgres://postgres:password@localhost:55433/postgres',

  pgrest: () =>
    process.env['PGRST_URL']
      ? null
      : 'PGRST_URL. The Supabase adapter speaks PostgREST, not Postgres:\n' +
        '      docker compose -f local/docker-compose.supabase.yml up -d --wait\n' +
        '      export PGRST_URL=http://localhost:55430',
}

/**
 * Throw unless every requirement is satisfied, naming all of them at once — a
 * developer fixing one variable at a time, one failed run at a time, is the
 * thing this is trying to avoid.
 */
export function requireIntegrationEnv(requires: readonly Requirement[]): void {
  const missing = requires
    .map((requirement) => HINTS[requirement]())
    .filter((hint): hint is string => hint !== null)

  if (missing.length === 0) return

  throw new Error(
    `Integration suite cannot run — missing configuration:\n\n  - ${missing.join('\n\n  - ')}\n\n` +
      'This suite FAILS rather than skips: a green skip would hide a real regression.',
  )
}

/** The database URL, having asserted it exists. */
export function databaseUrl(): string {
  requireIntegrationEnv(['database'])
  return process.env['DATABASE_URL'] as string
}

/** The PostgREST base URL, having asserted it exists. */
export function pgrestUrl(): string {
  requireIntegrationEnv(['pgrest'])
  return process.env['PGRST_URL'] as string
}
