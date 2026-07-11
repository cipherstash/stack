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

export type Requirement = 'cipherstash' | 'database' | 'pgrest' | 'userjwt'

/** Every variable protect-ffi's `AutoStrategy` needs to authenticate from the environment. */
const CS_VARS = [
  'CS_WORKSPACE_CRN',
  'CS_CLIENT_ID',
  'CS_CLIENT_KEY',
  'CS_CLIENT_ACCESS_KEY',
] as const

/** True when `stash auth login` has written a device profile. */
function hasProfile(): boolean {
  return existsSync(join(homedir(), '.cipherstash'))
}

/**
 * CipherStash credentials resolve from EITHER all four `CS_*` variables OR a
 * local `~/.cipherstash` profile written by `stash auth login`. A developer who
 * has logged in once needs no environment; CI, which has no profile, supplies
 * the vars.
 *
 * A PARTIALLY configured environment is neither, and is rejected. Accepting it
 * (as an earlier version did, on the presence of `CS_WORKSPACE_CRN` alone) let a
 * rotated or cleared secret through the gate, and the run then failed once per
 * test with `[encryption]: Not authenticated` — which names nothing and points
 * nowhere. That is precisely the "fail loudly, and say how to fix it" contract
 * this module exists to keep.
 *
 * The partial case is not merely under-configured, it is ambiguous: with a
 * profile on disk it is unclear whether the caller meant to override one field
 * or to use the environment wholesale. Refusing to guess is the honest answer.
 */
function cipherstashHint(): string | null {
  const missing = CS_VARS.filter((name) => !process.env[name])

  // Fully configured from the environment. Any profile is irrelevant.
  if (missing.length === 0) return null

  // Nothing in the environment: the profile is the intended source.
  if (missing.length === CS_VARS.length && hasProfile()) return null

  const preamble =
    missing.length === CS_VARS.length
      ? 'CipherStash credentials: none are configured.'
      : `CipherStash credentials are PARTIALLY configured — missing ${missing.join(', ')}.\n` +
        '    A partial environment is rejected rather than half-used: it would otherwise\n' +
        '    fail later with "[encryption]: Not authenticated", which names nothing.'

  return (
    `${preamble}\n` +
    `    Either set all four (${CS_VARS.join(', ')}),\n` +
    '    or unset them all and run `stash auth login` once (writes ~/.cipherstash,\n' +
    '    which AutoStrategy picks up).'
  )
}

const HINTS: Record<Requirement, () => string | null> = {
  cipherstash: cipherstashHint,

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

  userjwt: () =>
    process.env['USER_JWT']
      ? null
      : 'USER_JWT. The identity / lock-context suites bind a data key to an\n' +
        '    end-user JWT claim, so they need a real token:\n' +
        '      export USER_JWT=<a JWT for the workspace>',
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
