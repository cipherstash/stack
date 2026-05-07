---
"@cipherstash/wizard": minor
"stash": minor
---

Add plan-mode support to the wizard so `stash plan` can hand off to the CipherStash Agent. The wizard now accepts `--mode <plan|implement>` (default `implement` for back-compat). In plan mode it skips the column-selection TUI, forwards `mode: 'plan'` to the gateway (which returns a planning prompt whose deliverable is `.cipherstash/plan.md`), and skips the post-agent install/push/migrate and call-site-scan steps. Implement mode is unchanged.

`stash plan`'s handoff picker now offers all four targets (Claude Code, Codex, AGENTS.md, CipherStash Agent) — the wizard is no longer gated out of plan mode. `stash impl`'s picker is unchanged.
