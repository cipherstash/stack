---
'stash': minor
---

`stash init` is honest non-interactively — it no longer reports success for a
setup that didn't fully complete.

- **Fails on version skew.** A non-interactive run can't reconcile an
  already-installed `@cipherstash/*` package that's *older* than this CLI
  expects (it won't mutate an install without consent), so instead of warning
  and proceeding — scaffolding against mismatched packages and then claiming
  success — it now refuses with a non-zero exit and the exact align command.
  Interactive runs still offer to align. A *newer* install stays a warn (the
  install is likely fine; update the CLI instead).
- **No false "Setup complete".** If the EQL extension isn't installed at the
  end (and the integration isn't Prisma Next, which installs it via
  `migration apply`), the summary reads "Setup incomplete" and init exits
  non-zero, pointing at `stash eql install`.
- **Honest checkmarks.** The summary no longer claims "Database connection
  verified" (init resolves a URL but doesn't open a connection) — it now says
  "Database URL resolved" — and only shows "Encryption client scaffolded" when
  a client was actually written (skipped for Prisma Next).
- **No false "skills loaded".** The agent handoff prompt only points at the
  skills directory when skills were actually copied (a stripped build installs
  none), instead of telling the agent to read files that aren't there.
