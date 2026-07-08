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
  `Cannot find module 'stash'` from the config's `import`. A plain
  `stash eql install` still honours an existing config (later workflow commands
  rely on it) and offers to scaffold one otherwise. An explicit `--database-url`
  is a one-shot install: it resolves that URL directly and leaves the project
  untouched — no config or client is scaffolded, and an existing config is
  bypassed so the flag can't be silently overridden by a hand-edited literal
  `databaseUrl` (including one in a parent directory).
- As a safety net, `loadStashConfig` translates a missing-module load failure
  (a project that *has* a config but lacks the CLI packages) into the same
  actionable guidance for every command, instead of a jiti/Node stack trace.
