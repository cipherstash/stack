---
'stash': patch
---

Fix `stash impl` hanging on CI runners that set `CI=1` or `CI=TRUE`.

`stash impl` decided whether to prompt with an inline `process.env.CI !== 'true'`
check, which only recognised the exact lowercase spelling. On a CI runner that
sets `CI=1` or `CI=TRUE` and allocates a TTY, the command believed it was
interactive and blocked forever on the plan-summary confirmation or the
agent-target picker — a silent hang with no error and no timeout.

The gate now uses the shared `isInteractive()` helper, the same one `stash plan`
already used, which treats `1`/`true` in any case as CI. `stash impl` now takes
the non-interactive path on those runners, matching `stash plan`.
