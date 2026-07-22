---
'stash': patch
---

`stash plan` now reports the outcome that actually occurred instead of unconditionally printing `Plan drafted at .cipherstash/plan.md` and exiting 0 (#738). The plan file is written by the handed-off agent, so the command verifies it on disk after the handoff: "Plan drafted" appears only when the file exists; if a launched agent (Claude Code, Codex, or the wizard) exits without writing it, `plan` errors and exits non-zero so automation never proceeds against a plan that was never created; deferred handoffs (`--target agents-md`, or a CLI target that isn't installed) end with an honest "No plan drafted yet" hint; and a pre-existing plan the run didn't modify is reported as left unchanged rather than drafted.
