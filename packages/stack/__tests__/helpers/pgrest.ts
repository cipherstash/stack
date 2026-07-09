/**
 * A real PostgREST in front of a real Postgres, for the live supabase v3 suite.
 *
 * `SupabaseClientLike` is just `{ from(table): … }` (`src/supabase/types.ts`), so
 * a bare `PostgrestClient` satisfies the adapter with no anon key, no JWT, and
 * none of the Supabase auth stack. What it does give us is the one thing the
 * mock cannot: PostgREST actually parsing `prop:db_name::jsonb` aliasing selects
 * against a DOMAIN column, mapping `cs` to `@>`, re-parsing a double-quoted JSON
 * envelope inside `or=(…)`, and coercing a full storage envelope through the
 * `public.*` domain CHECK on every filter operand.
 */

import { PostgrestClient } from '@supabase/postgrest-js'
import type postgres from 'postgres'
import type { SupabaseClientLike } from '@/supabase/types'

export function makePostgrestClient(): SupabaseClientLike {
  const url = process.env.PGRST_URL
  if (!url) {
    throw new Error(
      'PGRST_URL is not set — makePostgrestClient() must only be called behind `describeLiveSupabasePgrest`',
    )
  }
  return new PostgrestClient(url) as unknown as SupabaseClientLike
}

/**
 * Ask PostgREST to reload its schema cache, then WAIT until it really has.
 *
 * PostgREST caches the schema at boot, and this suite creates its table in
 * `beforeAll`, long after that. Getting this wrong is subtle, so:
 *
 * DO NOT poll with a GET against the new table. PostgREST 12 self-heals a
 * cache miss by scheduling a reload and retrying THAT request, so the GET
 * starts succeeding while the cache reload is still in flight. A `POST` issued
 * in the window between then 404s — observed exactly this, cold: the probe GET
 * returned 200, the very next insert returned 404, and a later GET returned
 * 200 again. Polling reads therefore proves nothing about writes.
 *
 * Poll the ROOT endpoint instead. Its OpenAPI output is rendered FROM the
 * loaded schema cache, so a table appearing under `paths` means the reload has
 * actually landed and every verb will see it.
 *
 * `NOTIFY` needs `PGRST_DB_CHANNEL_ENABLED=true`; the self-heal covers us if it
 * is off, but slowly and only for reads — hence both.
 */
export async function reloadSchemaCache(
  sql: postgres.Sql,
  tableName: string,
  { timeoutMs = 30_000, intervalMs = 100 } = {},
): Promise<void> {
  await sql.unsafe(`NOTIFY pgrst, 'reload schema'`)

  const url = process.env.PGRST_URL
  const deadline = Date.now() + timeoutMs
  let lastStatus = 0

  while (Date.now() < deadline) {
    const response = await fetch(`${url}/`)
    lastStatus = response.status
    if (response.ok) {
      const spec = (await response.json()) as {
        paths?: Record<string, unknown>
      }
      if (spec.paths && Object.hasOwn(spec.paths, `/${tableName}`)) return
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }

  throw new Error(
    `PostgREST never loaded table "${tableName}" into its schema cache within ${timeoutMs}ms (last root status: ${lastStatus}). Is PGRST_DB_CHANNEL_ENABLED=true, and does the anon role have SELECT on the table?`,
  )
}
