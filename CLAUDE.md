# CipherStash Stack — Claude Code

The project instructions for this repo live in `AGENTS.md`, shared by every agent
that works here. It is imported below rather than duplicated, so there is exactly
one source of truth.

@AGENTS.md

## Before you finish

Two rules from `AGENTS.md` are the ones most often missed. They are repeated here
because both fail silently — nothing in CI catches either:

1. **Check the skills.** If you changed a package's public API, the CLI command
   surface, or a user-facing workflow, update the affected `skills/*/SKILL.md` in
   the same PR. These files ship inside the `stash` npm tarball and get copied
   into customer repos, so drift becomes wrong guidance in someone else's
   codebase. See "Agent Skills — these ship to customers".

2. **Add a changeset** when the change affects a published package's surface —
   including a skills-only change, since `skills/` ships in the `stash` tarball.

## Package-specific notes

`packages/cli` has its own `AGENTS.md` covering the two Vitest configs (unit vs.
the pty-driven e2e suite) and when each needs to run. Read it before touching
`packages/cli/src/bin/main.ts`, `src/messages.ts`, or the command registry.
