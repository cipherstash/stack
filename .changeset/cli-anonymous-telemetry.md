---
'stash': minor
---

Add anonymous, opt-out usage analytics to the `stash` CLI, plus a
`stash telemetry [status|enable|disable]` command to manage it.

Only coarse events are collected — command name, CLI version, OS/arch, Node
version, success/failure, duration, and a coarse caller class (e.g.
`claude-code`, `cursor`, `interactive`) derived from environment markers so we
can gauge agent- vs human-driven usage. Plaintext, schema, table/column names,
connection strings, argument values, and any session/trace identifier are never
collected — enforced by a property-key allowlist at the emitter boundary plus
closed-vocabulary coercion of every argv- or error-derived value (unrecognised
commands, subcommands, and error class names all collapse to `<other>`). A
one-time notice is shown on first run, and nothing is sent on that run.

Telemetry is off by default in CI and can be disabled with `DO_NOT_TRACK=1`
(the cross-tool standard), `STASH_TELEMETRY_DISABLED=1`, or
`stash telemetry disable` (persisted to `~/.cipherstash/telemetry.json`).

Events are sent via a first-party proxy and never block or slow the CLI. The
feature ships dormant — no events are sent until a PostHog project key is
embedded at release. Updates the `stash-cli` skill to document the command and
opt-out controls.
