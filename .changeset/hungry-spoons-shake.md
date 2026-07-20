---
'stash': patch
---

Fix `stash impl` and `stash init` hanging on CI runners that allocate a TTY.

Three prompts decided whether to run interactively without going through the
shared TTY helper, so on a CI runner with an allocated TTY they rendered a clack
prompt and blocked forever on `/dev/tty` — a silent hang with no error and no
timeout:

- `stash impl` gated on an inline `process.env.CI !== 'true'`, which only
  recognised the exact lowercase spelling. Runners that set `CI=1` or `CI=TRUE`
  blocked on the plan-summary confirmation or the agent-target picker.
- `stash init`'s offer to chain into `stash plan`, and its Proxy-vs-SDK
  question, gated on `process.stdout.isTTY` and did not consult `CI` at all —
  so they hung on any CI runner with a TTY, whatever the spelling. Gating on
  stdout was also the wrong stream: a redirected stdin still hangs a prompt.

All three now use the shared `isInteractive()` helper (stdin is a TTY and `CI`
is not set to `1`/`true` in any case), matching `stash plan`. Non-interactive
runs take the path they always should have: `stash init` skips the chain offer
and prints the `plan --target` hint, the Proxy-vs-SDK question defaults to
SDK-only, and `stash impl` proceeds without prompting.
