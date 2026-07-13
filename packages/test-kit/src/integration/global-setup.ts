import {
  databaseUrl,
  dbVariant,
  installEqlV3,
  type Requirement,
  requireIntegrationEnv,
} from '../index.ts'

/**
 * Fail fast, before a single container second is spent, and install EQL v3 once
 * per run through the real `stash eql install`.
 *
 * Runs in Vitest's `globalSetup`, so a misconfigured run reports one clear error
 * rather than the same error once per test file.
 */
export async function setup(): Promise<void> {
  const variant = dbVariant()

  // Every integration suite encrypts, so CipherStash credentials are always
  // required. The Supabase variant additionally needs PostgREST — the adapter
  // does not speak Postgres.
  const requirements: Requirement[] = ['cipherstash', 'database']
  if (variant === 'supabase') requirements.push('pgrest')
  requireIntegrationEnv(requirements)

  await installEqlV3(databaseUrl(), variant)
}
