---
'stash': patch
---

`stash init` installs the agent skills again, and does it first.

Since 1.0.0-rc.4 the only callers of the skills installer were the `plan` and
`impl` handoff steps, which `stash init` never reaches — so `stash@1.1.0`
installed no `stash-*` skills for anyone, in any mode. The most common flow, a
coding agent running `npx stash init --supabase` inside a project, completed
with a green summary, a plausible-looking `.cipherstash/context.json`, and zero
guidance: the skills sat unread in `node_modules/stash/dist/skills/` unless the
agent thought to go digging. Fixes #923.

Init now copies the per-integration skills into `.claude/skills/` (Claude Code
detected via the `claude` binary or a `.claude/` directory) and `.codex/skills/`
(Codex), installing to both when both are detected, and records them in
`context.json`.

It runs as init's **first** step, ahead of authentication. Installing skills
needs no network, no credentials and no database, while authenticate,
resolve-database and install-eql each need one and each can exit non-zero —
so the guidance now survives a run that fails partway, which is when it is
needed most. One behaviour change falls out of that: a run cancelled at the
first prompt leaves the skills directory behind where previously it wrote
nothing.

Also:

- **New optional `stash init --target <claude-code|codex>`** names the skills
  destination and skips detection. Unlike `plan --target` / `impl --target` it
  selects the destination only — `init` still performs no handoff. Existing
  invocations are unaffected.
- **The summary reports the outcome either way.** A run that installs nothing
  now says so, and prints the command that will install them, instead of a
  silent `installedSkills: []`.
- **`--target` is validated properly on `init`, `plan` and `impl`.** A
  trailing `--target` with no value, and `--target=`, were both treated as
  "flag absent" — so the command silently did whatever it does with no flag at
  all, rather than telling you the value was missing. All three commands share
  one validator now.
- **A later handoff no longer erases the record.** `stash plan --target
  agents-md` installs no skill directories of its own and used to overwrite
  `installedSkills` with an empty list, dropping skills that were on disk.
  Deliveries are merged across hops now.
