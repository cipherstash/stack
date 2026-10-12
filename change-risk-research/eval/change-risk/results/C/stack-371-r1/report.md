## Change risk: Ready for normal review

**Impact if something goes wrong:** low · **Verification confidence:** high · `cf8ebc2388..d257468c35`

Pure refactor of the @cipherstash/cli package: user-facing strings that E2E tests assert on are moved into a new `src/messages.ts` const object, and the CLI entrypoint, `auth` command and `selectRegion()` prompt now interpolate those constants. Every extracted constant reproduces the previous literal byte-for-byte (including the ': ' composition for unknown-command errors), so rendered CLI output is unchanged. The new module is bundled by tsup into dist/bin/stash.js, adds no dependency and is not exported from the library entry. E2E tests import the same constants; the `db migrate` assertion is tightened from a substring to the full message. CI 'Run Tests' (which builds and runs the CLI E2E suite) passed on head. No material failure scenario identified.

No material failure scenarios identified.

### Recommended controls

- Optional: future copy edits in messages.ts deserve a human look, since the E2E tests now follow them automatically and will not flag a wording change. (review_focus; )

### What this assessment could not see

- ci.json gives only job-level conclusions; step-level logs for the CLI E2E step were not available. Passing E2E is inferred from the 'Run Tests' job succeeding with that step in it, not from a test log.
- Tests were not run locally (no network; dependencies not installed). Verification relies on CI results and code reading.
- Collector flagged usual co-changes (db/install.ts, init/providers/supabase.ts) absent here; the diff touches no db install or init logic, so these were not investigated further. Minor; the co-change signal reflects past feature work on stash.ts, not a dependency of this refactor.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
