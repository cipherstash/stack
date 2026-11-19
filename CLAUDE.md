# CipherStash Stack — Claude Code

The project instructions for this repo live in `AGENTS.md`, shared by every agent
that works here. It is imported below rather than duplicated, so there is exactly
one source of truth.

@AGENTS.md

## Agent skills

### Issue tracker

Issues are tracked in GitHub Issues for `cipherstash/stack`. See
`docs/agents/issue-tracker.md`.

### Triage labels

Use the five default triage labels. See `docs/agents/triage-labels.md`.

### Domain docs

Use a multi-context layout rooted at `CONTEXT-MAP.md`, with package-specific
`CONTEXT.md` files added as needed. See `docs/agents/domain.md`.

### Plain language

`.claude/skills/plain-language` is the plain-language skill from
https://github.com/auxesis/plain-language-skill, copied at commit `b001fa61`.
Load it when you write or review prose for a person: a document, a plan, a pull
request description, a commit message, or a code comment. It is an internal
skill for agents working on this repository. It lives in `.claude/skills/`, not
`skills/`, so it does not ship to customers.

The copy holds the upstream `skills/plain-language` folder plus its `LICENSE`
and `NOTICE`. The upstream hooks that check every reply were not copied. To
update it, copy the same files from a newer commit and change the commit above.
The checker runs without any packages beyond Python's standard library:

```bash
python3 .claude/skills/plain-language/scripts/check.py path/to/file.md
```

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

`languages/typescript/packages/cli` has its own `AGENTS.md` covering the two Vitest configs (unit vs.
the pty-driven e2e suite) and when each needs to run. Read it before touching
`languages/typescript/packages/cli/src/bin/main.ts`, `languages/typescript/packages/cli/src/messages.ts`, or the command
registry at `languages/typescript/packages/cli/src/cli/registry.ts`.
