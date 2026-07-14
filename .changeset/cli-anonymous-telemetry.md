---
'stash': minor
---

Add anonymous, opt-out usage analytics to the `stash` CLI, plus a
`stash telemetry [status|enable|disable]` command to manage it.

Only coarse events are collected — command name, CLI version, OS/arch,
success/failure, and duration. Plaintext, schema, table/column names, connection
strings, and argument values are never collected (enforced by a property
allowlist at the emitter boundary). A one-time notice is shown on first run, and
nothing is sent on that run.

Telemetry is off by default in CI and can be disabled with `DO_NOT_TRACK=1`
(the cross-tool standard), `STASH_TELEMETRY_DISABLED=1`, or
`stash telemetry disable` (persisted to `~/.cipherstash/telemetry.json`).

Events are sent via a first-party proxy and never block or slow the CLI. The
feature ships dormant — no events are sent until a PostHog project key is
embedded at release. Updates the `stash-cli` skill to document the command and
opt-out controls.
