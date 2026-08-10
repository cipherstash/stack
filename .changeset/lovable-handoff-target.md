---
'stash': minor
---

Add a `lovable` handoff target to `stash plan` and `stash impl` (`--target lovable`, plus a new agent-target picker entry). It writes the same AGENTS.md as the editor-agent handoff — doctrine plus the per-integration skills inlined — but the next-steps guidance is Lovable-specific: commit and push the generated files through Lovable's GitHub sync, then add a Knowledge note in the Lovable project settings pointing the agent at `AGENTS.md` and `.cipherstash/setup-prompt.md`. Without repo-local guidance, Lovable's agent answers CipherStash questions from stale training data (the pre-EQL-v3 "needs a Postgres extension and superuser" story) and talks users out of a supported Supabase setup.
