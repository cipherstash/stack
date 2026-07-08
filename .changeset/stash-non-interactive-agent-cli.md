---
"stash": minor
---

Add non-interactive / agent-friendly affordances so `stash init` and
`stash auth login` can run without a TTY (agents, CI, pipes). All changes are
additive — interactive behaviour in a real terminal is unchanged.

- `--region <slug>` / `STASH_REGION` on `stash auth login` and `stash init`
  skip the interactive region picker. An unknown or missing region in a
  non-TTY context now exits with an actionable message instead of hanging on
  the picker (region resolution mirrors the `DATABASE_URL` resolver's
  `TTY && !CI` gate).
- `stash auth login --json` emits newline-delimited device-code events. The
  first event (`authorization_required`) carries the verification URL, so an
  agent can trigger auth and hand the browser step to a human — only a human
  completes it in the browser. `--no-open` suppresses the browser launch.
- `stash auth regions` lists the regions valid for `--region` / `STASH_REGION`;
  `stash auth regions --json` emits `[{ slug, label }]` for programmatic use.
