---
name: review-repo-rules
description: The repo-rules lens of the automated Claude pull-request review for cipherstash/stack — the AGENTS.md rules no CI job enforces: stale customer-facing skills, missing or mis-scoped changesets, stale repository-layout docs, Linear IDs in public files. Use when the review workflow names this lens, or to run the same review locally on a branch.
---

# Review lens: repo-rules

Internal skill — lives in `.claude/skills/` on purpose; `skills/` ships to
customers inside the `stash` tarball and this must not. It is loaded by
`.github/workflows/claude-review.yml` from the base branch.

You are one of several parallel lenses. Report only breaches of this
repository's own rules; bugs and security issues belong to the other lenses.
`AGENTS.md` (restored from the base branch before you start) is the source of
truth — quote the rule you are applying.

## What to check

1. **Customer-facing skills.** If the diff changes a package's public API, the
   `stash` CLI command surface (commands, flags, prompts), or a user-facing
   workflow, find the matching `skills/*/SKILL.md` in the table under "Agent
   Skills — these ship to customers" in `AGENTS.md`. Report when that skill
   now says something the change made wrong, or when it is untouched but
   documents the changed surface. Read the skill; do not report on file names
   alone.
2. **Changesets.** A change to a published package's behaviour or surface
   needs a file under `.changeset/`. Report when:
   - one is missing (test-only, internal-refactor and repo-tooling changes do
     not need one);
   - a change to `skills/` has no `stash` changeset — skills ship in that
     tarball, so a skills-only change is not internal;
   - a changeset names the wrong package or a bump level that does not match
     the change (a removed export is not a `patch`);
   - a file uses the `.md.deferred` suffix.
3. **Repository layout and meta files.** If the diff adds, removes, or renames
   a package, example, skill, or subpath export, the "Repository Layout"
   section of `AGENTS.md` and the package list in `SECURITY.md` must change in
   the same pull request.
4. **Linear issue IDs in public places.** `skills/**` must not contain Linear
   IDs (`CIP-1234` style). GitHub issue numbers are fine.
5. **Workflows under a package.** A workflow added under a package's own
   `.github/` never runs — GitHub reads only the repository root.

## How to report

- Inline comments on the changed line that triggers the rule, quoting it.
- For a missing file (no changeset, untouched skill), put the finding in the
  summary instead, naming the file that should change and why.
- Do not report a rule CI already enforces: Biome, type checks, and the
  `scripts/__tests__` guards fail on their own.
