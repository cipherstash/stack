---
'@cipherstash/wizard': patch
---

Drop the last `stash db push` references from the wizard's output, and name the
migration files a failed sweep rewrote before it stopped.

- The "Post-agent steps complete" changelog line claimed `db push` had run.
  `stash db push` was retired with the CipherStash Proxy lifecycle and
  `runPostAgentSteps` never invoked it; the line now reports what the step
  actually does (package install, `eql install`, migrations). The `--plan` help
  text no longer promises "no db pushes" either.
- When a candidate directory's ALTER COLUMN sweep threw, the wizard reported the
  failure but skipped the per-directory report, so files it had already rewritten
  on disk went unnamed. It now lists them ("Rewrote N migration file(s) in
  drizzle/ before the sweep stopped"), matching `stash eql migration --drizzle`.
  The rewritten SQL is additive and the wizard still fails before the migrate
  prompt, so this changes what the user is told, not what runs.
