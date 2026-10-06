---
status: accepted
---

# Claude review lenses are base-branch skills, and Claude only reads

The automated Claude pull-request review (`.github/workflows/claude-review.yml`)
is split into parallel lenses. What each lens looks for lives in a skill —
`.claude/skills/review-<lens>/SKILL.md` for this repository's lenses, the
`company-skills` plugin from a pinned `cipherstash/skills` commit for
organisation lenses, and a pinned `anthropics/claude-code` commit for the
`code-review` plugin — never in workflow YAML. Skills are read from the base
branch: the action restores `.claude/` and the root `CLAUDE.md`, and the
workflow restores every `CLAUDE.md`, `CLAUDE.local.md` and `AGENTS.md` at any
depth (removing ones the base lacks), so a pull request cannot rewrite the
instructions its own review follows. Plugins are installed from local
checkouts at full commit SHAs because the action cannot pin a marketplace URL.

Claude is read-only. It reads the diff through scoped `gh pr diff` /
`gh pr view`, may leave inline comments, and returns its summary as structured
output; a plain shell step publishes that summary. Claude cannot edit files,
commit, push, approve, label, merge, or post general comments, so a review
manipulated by pull-request content can do no more than leave a misleading
comment. Tag mode, which would add a progress comment at the cost of commit
and push rights, was rejected for the same reason.

## Consequences

- Changing what a lens checks is an edit to a markdown file, reviewed like
  code, and takes effect only once it reaches `main`.
- A new or changed lens cannot be verified on the pull request that introduces
  it; verification is a test pull request after merge.
- The workflow file itself still runs from the pull request (the action's
  default-branch match is skipped when it is given the job token), so the
  guarantee covers instructions, not the plumbing. Only contributors with write
  access can open pull requests the review runs on.
- Organisation lenses and the `code-review` plugin change only through a pull
  request here that bumps a pinned SHA.
- Summaries are found by author and a leading per-lens marker, so lenses
  cannot overwrite each other's comment.
- A lens that skips, crashes, stops early, or returns no summary fails its
  check. The `code-review` plugin stops early once Claude has commented on a
  pull request; if it counts the lens summaries as such, its check is red
  on every run after the first until that is revisited.
