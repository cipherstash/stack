---
"stash": patch
---

Render per-command `--help` from the command-descriptor registry, and slim the
global banner. This is the documented follow-on to the manifest/registry work in
`docs/plans/cli-help-and-manifest.md`.

- `stash <command> --help` now prints command-specific help instead of the global
  banner. A leaf command (`stash eql install --help`, `stash auth login --help`)
  shows its usage, summary, long description, flags, and examples; a command
  group (`stash eql --help`, `stash auth --help`) lists its subcommands and points
  at their own `--help`. All of it renders from `src/cli/registry.ts`, so it can't
  drift from `stash manifest`.
- `-h` is now honoured after a command too (`stash eql install -h`), not just as a
  bare `stash -h`.
- The global `stash --help` banner no longer inlines every command's flags; it
  lists the commands and directs users to `<command> --help` for the detail.
