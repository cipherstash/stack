---
"stash": patch
---

`stash status` now detects when a plan has been drafted but the rollout hasn't started yet. Previously, with no `cs_migrations` activity, status reported "your encryption rollout has not begun" and pointed the user at `stash plan` — even when `.cipherstash/plan.md` already existed. It now recognises that case and points the user at `stash impl` to execute the plan instead.
