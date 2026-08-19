---
name: meta-pr-creation
description: How an agent authors branches, commits, and pull requests on cipherstash/stack — naming, signed commits, the changeset/skills/meta-file checklist, and PR body structure with dumbed-down wording. Use when committing work or opening/updating a PR.
---

# Authoring PRs as an agent

Internal skill — lives in `.claude/skills/` on purpose. `skills/` ships to
customers inside the `stash` tarball; this must not.

## Branch and commits

- Branch names are type-prefixed slugs: `docs/skill-psl-functional-indexes`,
  `fix/…`, `feat/…`, `chore/…`. Never commit to `main`.
- Commit subjects are conventional: `type(scope): imperative summary` —
  `docs(skills): …`, `fix(stack-prisma): …`. The body explains **why** and the
  mechanism, not a list of what changed (the diff shows that). Reference the
  GitHub issue the commit serves.
- **Commits must be signed.** `commit.gpgsign` is on, but verify before
  pushing:

  ```bash
  git log --format='%h %G? %s' main..HEAD   # G = signed, N = unsigned
  ```

  An unsigned commit (`N`) in the stack: `git rebase --force-rebase main`
  re-commits everything signed, then `git push --force-with-lease`. Always
  `--force-with-lease`, never bare `--force`.

## Before opening the PR

The authoritative checklist is `AGENTS.md` § "Adding Features Safely" — read
it, don't work from memory. The three most-missed items:

1. **Changeset** — required when the change touches a published package's
   surface, *including* a `skills/`-only change (those ship in the `stash`
   tarball, so they need a `stash` patch changeset). A `.claude/`-only change
   is internal: no changeset.
2. **Skills check** — a change to a public API, CLI surface, or user-facing
   workflow must fix the affected `skills/*/SKILL.md` in the same PR
   (package→skill map in `AGENTS.md`).
3. **Meta files** — adding/removing/renaming a package, example, skill, or
   subpath export must update `AGENTS.md` Repository Layout and `SECURITY.md`.

Then run: `pnpm run code:fix`, `pnpm --filter <pkg> build`,
`pnpm --filter <pkg> test`.

## PR body

Same wording rule as [meta-issue-creation](../meta-issue-creation/SKILL.md):
**dumbed down** — assume the reviewer is new to CipherStash, stack, and EQL.
Define product terms at first use; say what breaks or improves in the user's
world, not just the code's.

Sections, in order:

- **Summary** — what and why, two or three plain sentences. Lead with the
  user-visible effect.
- **Changes** — grouped by area, one line each.
- **Verification** — exactly what was run and what it showed. Honest: a
  failing or skipped check is stated, not omitted. "Verified against the 0.17
  dist" beats "should work".
- **Related** — `Closes #N` / `Refs #N` for the GitHub issues this serves;
  cross-repo refs in full `owner/repo#N` form.
- **Review notes** *(optional)* — where to look first, and anything
  deliberately deferred with the reason.

Reference wording traps (same as issues):

- `#N` **only** as a real GitHub issue/PR reference — GitHub autolinks every
  `#N`, so "option #2" mints a bogus link. Write "option 2".
- **Never** reference internal Linear issues (`CIP-…`) in PRs, commits, or
  comments — GitHub is public.

## Mechanics

- `gh pr create --title '…' --body '…'` (title follows the commit-subject
  convention).
- Force-pushing a branch with an open PR is fine (rebases, re-signs) — but
  say so in a PR comment when the rewrite changes more than commit hashes.
- Don't merge, close, or mark ready-for-review without being asked.
