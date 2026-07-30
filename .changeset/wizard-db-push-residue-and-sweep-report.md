---
'@cipherstash/wizard': patch
---

Drop the last `stash db push` references from the wizard's output, and name the
migration files a failed sweep rewrote before it stopped.

- The "Post-agent steps complete" changelog line claimed `db push` had run.
  `stash db push` was retired with the CipherStash Proxy lifecycle and
  `runPostAgentSteps` never invoked it; the line now reports what the step
  actually does (package install, `eql install`, migrations). The `--plan` help
  text no longer promises "no db pushes" either, and the package README — which
  ships in the tarball — no longer lists `db push` as a prerequisite or a
  post-agent step.
- When a candidate directory's ALTER COLUMN sweep threw, the wizard reported the
  failure but skipped the per-directory report, so files it had already rewritten
  on disk — and statements it had flagged — went unnamed. It now lists them
  ("Rewrote N migration file(s) in drizzle/ before the sweep stopped", followed by
  the flagged statements and their reasons), matching
  `stash eql migration --drizzle`.
- The cross-directory summary ("Rewrote N migration file(s) in the drizzle output
  to add staged encrypted columns while preserving the source columns") is now
  suppressed when any directory failed to sweep. It is built from a total that
  counts clean and partially-swept directories alike, so on that path it restated
  the reassuring framing the per-directory report deliberately drops. A *flagged*
  statement still prints the summary — there the sweep finished and the count is
  accurate.

Both are reporting-only: the rewritten SQL is additive and the wizard still
throws before the migrate prompt, so this changes what the user is told, not what
runs.
