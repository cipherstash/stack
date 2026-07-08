---
"stash": minor
---

Add a command-descriptor registry and `stash manifest --json` — a structured,
versioned command surface for the docs generator and agents to consume instead
of scraping `--help`.

- `stash manifest --json` emits `{ name, version, groups[] }`, where each command
  carries its summary, optional long description, examples, and flags. `version`
  comes from the CLI's own `package.json`, so a page generated from the manifest
  is always stamped with the version it describes.
- `stash manifest` (no flag) prints a grouped, human-readable command list.
- The registry (`src/cli/registry.ts`) is the single source of truth for command
  metadata. This is phase 1 of `docs/plans/cli-help-and-manifest.md`; rendering
  the top-level and per-command `--help` from the same registry is the
  documented follow-on.
