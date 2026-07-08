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
- The registry (`src/cli/registry.ts`) is intended to become the single source of
  truth for command metadata. This is phase 1 of
  `docs/plans/cli-help-and-manifest.md`; it is additive — `bin/main.ts` still
  hand-maintains the `HELP` string that renders `--help`, so until the documented
  follow-on renders `--help` from the registry the two are kept in sync by hand.
