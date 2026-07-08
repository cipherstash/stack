---
"stash": patch
---

Fix two config-scaffold dead-ends in the CLI (#578, #579).

- **Missing config is now actionable.** When a command can't find
  `stash.config.ts`, the error recommends `stash init` / `stash eql install`
  (runner-aware) instead of only telling you to hand-write the file.
- **Standalone `stash eql install` no longer crashes with a raw
  `Cannot find module 'stash'`.** The scaffolded `stash.config.ts` imports
  `stash` (and the client it points at imports `@cipherstash/stack`), which
  only resolve once those packages are project dependencies — something only
  `stash init` did. `eql install` now checks for them after scaffolding and
  offers to install the missing ones (or prints the exact install commands in
  non-interactive contexts). As a safety net, `loadStashConfig` translates a
  missing-module load failure into the same actionable guidance for every
  command, rather than dumping a jiti/Node stack trace.
