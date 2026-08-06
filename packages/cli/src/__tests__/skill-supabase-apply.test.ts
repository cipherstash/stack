import { readdirSync, readFileSync } from 'node:fs'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const CLI_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const REPO_ROOT = resolve(CLI_ROOT, '../..')
const SKILLS_ROOT = resolve(REPO_ROOT, 'skills')

/**
 * `supabase migration up` applies to the **local** database. The remote forms
 * are `supabase db push` and `supabase migration up --linked`.
 *
 * Skills ship inside the `stash` tarball and are copied into customer repos, so
 * naming the local command as the remote one is not a typo — it means a user
 * follows the instructions, believes production has EQL, and every encrypted
 * query there fails at runtime. Nothing else checks these files, which is why
 * this guard exists (same reasoning as the version-pin guard in
 * `release-train.test.ts`).
 *
 * The rule: any `supabase migration up` in a shipped skill must either carry
 * `--linked` or be immediately qualified as the local command ("… applies to
 * the local database"). A nearby "locally" is not enough — the wording this
 * guard exists to catch, "apply with `supabase migration up` (or `supabase db
 * reset` locally)", has one, attached to the other command.
 */
const SKILL_FILES = readdirSync(SKILLS_ROOT, { withFileTypes: true })
  .filter((entry) => entry.isDirectory())
  .map((entry) => ({
    skill: entry.name,
    body: readFileSync(resolve(SKILLS_ROOT, entry.name, 'SKILL.md'), 'utf8'),
  }))

describe('skills — Supabase apply commands', () => {
  it('finds skills to check (a moved directory must not silently pass)', () => {
    expect(SKILL_FILES.length).toBeGreaterThan(0)
  })

  it.each(
    SKILL_FILES,
  )('$skill never presents a bare `supabase migration up` as the remote apply', ({
    body,
  }) => {
    // Collapse wrapping and drop markdown emphasis first: the qualifier
    // routinely lands on the next source line or arrives as `**local**`, and
    // either would fail the match on formatting rather than content.
    const prose = body.replace(/\s+/g, ' ').replace(/[*`_]/g, '')

    for (const match of prose.matchAll(/supabase migration up/g)) {
      // Only what immediately follows the command counts. A window wide
      // enough to find a "local database" elsewhere in the sentence accepts
      // the very wording this guard rejects — "apply with supabase migration
      // up (or supabase db reset locally, once the local database exists)"
      // qualifies the other command, not this one.
      const following = prose.slice(match.index + match[0].length)

      expect(
        following.slice(0, 60),
        '`supabase migration up` applies to the LOCAL database — add `--linked`, say "applies to the local database", or use `supabase db push` for remote',
      ).toMatch(/^(?: --linked\b| applies to the local database\b)/i)
    }
  })

  /**
   * `supabase migration repair --status applied <version>` writes a ledger row
   * and runs no SQL. That is the right move for a back-dated install on a
   * remote that already HAS EQL — pushing the file there re-runs a bundle
   * opening with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`. It is unrecoverable on
   * a remote that does not: the row asserts SQL ran that never did, so no later
   * push ever installs EQL, and the first `eql_v3` reference fails with nothing
   * pointing at the cause. Every other remedy in this area fails loudly and can
   * be retried; this one fails silently and cannot.
   *
   * So the rule: wherever a shipped skill recommends the ledger-only repair, a
   * command that establishes the remote's actual EQL state must appear shortly
   * BEFORE it. Before, because a check printed after the repair verifies
   * nothing — the row is already written. `eql_v3.version()` specifically,
   * because it is created by the bundle's closing statements and so cannot
   * resolve on a half-applied install, unlike the `eql_v3` schema itself.
   */
  it.each(
    SKILL_FILES,
  )('$skill never recommends the ledger-only repair without a check above it', ({
    body,
  }) => {
    // Same wrap-collapsing as above, minus the `_` strip: the marker here is
    // `eql_v3.version()`, which that strip would turn into `eqlv3.version()`.
    const prose = body.replace(/\s+/g, ' ').replace(/[*`]/g, '')

    for (const match of prose.matchAll(/migration repair --status applied/g)) {
      // A paragraph's worth of lead-in. Wide enough for the sentence that
      // introduces the check plus the one that explains what its output means,
      // narrow enough that an `eql_v3.version()` mention elsewhere in the
      // document cannot stand in for one attached to this recommendation.
      const preceding = prose.slice(Math.max(0, match.index - 700), match.index)

      expect(
        preceding,
        '`migration repair --status applied` writes a ledger row for SQL that may never have run — an unrecoverable state on a remote without EQL. Print the `select eql_v3.version()` check above this recommendation, not after it',
      ).toContain('eql_v3.version()')
    }
  })
})
