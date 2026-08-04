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
})
