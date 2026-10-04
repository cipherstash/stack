// The `/install` subpath, NOT the barrel: the barrel reaches `needle-for.ts`,
// which imports stack source through the `@/` alias, and bench has no
// `stackSourceAlias` in its vitest config (it consumes stack through its
// published dist/ exports). `install.ts` depends on node builtins only.
import { installEqlV3 } from '@cipherstash/test-kit/install'
import { getDatabaseUrl } from './db.js'

/**
 * Install EQL v3 once per run, before any suite applies `sql/schema.sql`.
 *
 * The fixture schema declares its columns as the concrete `eql_v3_*` domains, so
 * the bundle has to be in the database before the first `CREATE TABLE`. Doing it
 * here rather than in a CI-only step means the local `pnpm test:local` path and
 * the CI path are the same path — the previous arrangement had the workflow rely
 * on an EQL-v2-preinstalled image while the schema had already moved to v3, and
 * nothing connected the two.
 *
 * Runs through the real `stash eql install`, matching the integration suites'
 * harness (`@cipherstash/test-kit`'s `integration/global-setup.ts`): an installer
 * regression fails here instead of hiding behind a test-only SQL apply.
 *
 * Unlike those suites this needs NO CipherStash credentials — `installEqlV3`
 * wants only a database URL — which keeps `db-only.test.ts` the credential-free
 * smoke test it is meant to be.
 */
export async function setup(): Promise<void> {
  // EXPLICIT, never inferred from the environment. `dbVariant()` would guess
  // from `PGRST_URL`, and bench's compose stack happens to define a PostgREST
  // it never talks to — a guess here would silently apply the Supabase grants.
  await installEqlV3(getDatabaseUrl(), 'postgres')
}
