---
'stash': minor
---

`stash plan --complete-rollout` is now automatable and has an honest exit code.
It skips the production-deploy gate, so it needs explicit consent — previously
that was an interactive prompt with no bypass, so a non-interactive run
auto-cancelled (default-no) and exited **0** without drafting a plan, leaving
automation to assume a plan existed.

- New `--yes` flag confirms the gate-skip without a prompt (for CI/agents).
- Without `--yes`, a non-interactive `--complete-rollout` run now **refuses
  with a non-zero exit** and points at `--yes`, instead of silently succeeding.
- Interactive behaviour is unchanged (default-no confirm).
