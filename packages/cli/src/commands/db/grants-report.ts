import * as p from '@clack/prompts'
import type { InstallResult } from '@/installer/index.js'

/**
 * Report the Supabase-grants outcome of an `EQLInstaller.install()` run:
 * either everything ran, or the owner-scoped default-privilege statements
 * were deferred (the connecting role is not a member of `postgres`) and must
 * be surfaced for the operator to apply with sufficient privileges.
 */
export function reportSupabaseGrantsOutcome(result: InstallResult): void {
  if (result.deferredGrantsSql === null) {
    p.log.success('Supabase role permissions granted.')
    return
  }
  p.log.success(
    'Supabase role permissions granted for existing objects. The default-privilege statements below were skipped (they require membership of `postgres`).',
  )
  p.note(result.deferredGrantsSql.trim(), 'Deferred SQL — run as postgres')
}
