---
'stash': patch
'@cipherstash/wizard': patch
---

Fixed: a change to `skills/` could ship a stale copy of that skill.

Both CLIs copy the repo-root `skills/` into their bundle at build time
(`dist/skills`), which `stash init` then installs into a customer's
`.claude/skills/` or `.codex/skills/`. That directory sits outside the package,
so it was not part of the build's declared inputs — a skills-only edit did not
invalidate the cached build. Once the build began declaring its output
directory, a cache hit stopped being merely stale and started actively restoring
the previous `dist/skills` over the tree, so an edited skill could be published
with the pre-edit text while the source file on disk was correct and CI green.

The two builds now declare the skills directory as an input, and a test pins
that coupling so it cannot come undone.
