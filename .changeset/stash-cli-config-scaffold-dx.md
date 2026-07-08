---
"stash": patch
---

Fix two config-scaffold dead-ends in the CLI (#578, #579).

- **Missing config is now actionable.** When a command that needs a
  `stash.config.ts` can't find one, the error recommends `stash init` /
  `stash eql install` (runner-aware) instead of only telling you to hand-write
  the file.
- **`stash eql install` no longer requires a `stash.config.ts`.** It only needs
  a database URL, so it now resolves one directly (`--database-url` → env →
  `supabase status` → prompt) instead of scaffolding a config and loading it.
  That means a standalone `npx stash eql install --database-url ...` works in a
  bare project with **zero dependencies** — no more crash with a raw
  `Cannot find module 'stash'` from the config's `import`. An existing config is
  still honoured (later workflow commands rely on it), and a fresh one is offered
  as a convenience for the rest of the workflow rather than being a prerequisite.
- As a safety net, `loadStashConfig` translates a missing-module load failure
  (a project that *has* a config but lacks the CLI packages) into the same
  actionable guidance for every command, instead of a jiti/Node stack trace.
