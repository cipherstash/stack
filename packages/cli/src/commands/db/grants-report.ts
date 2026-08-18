import * as p from '@clack/prompts'
import type { InstallResult } from '@/installer/index.js'

/**
 * Report the Supabase-grants outcome of an `EQLInstaller.install()` run.
 *
 * When the connecting role is not a member of `postgres`, the owner-scoped
 * `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements were skipped. That
 * is reported as information, not as work the operator owes: the statements
 * only cover EQL objects `postgres` might create later outside stash tooling,
 * and every `stash eql install`/`eql upgrade` re-grants all objects anyway
 * (the generated Supabase migration embeds the grants too). On platforms
 * where nobody can act as `postgres` — Lovable's `sandbox_exec`, for one —
 * there is nothing to do and nothing missing.
 */
export function reportSupabaseGrantsOutcome(result: InstallResult): void {
  if (result.deferredGrantsSql === null) {
    p.log.success('Supabase role permissions granted.')
    return
  }
  p.log.success('Supabase role permissions granted for all existing objects.')
  p.log.info(
    'Skipped the optional `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements — they require membership of `postgres`, and are only needed if EQL objects are later created outside stash tooling (stash re-grants every object on each install/upgrade). To apply them anyway, use the SQL below via your migration tool or the Supabase SQL editor.',
  )
  p.note(result.deferredGrantsSql.trim(), 'Optional SQL — requires postgres')
}
