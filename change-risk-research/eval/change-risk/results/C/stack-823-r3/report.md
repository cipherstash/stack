## Change risk: Changes or verification required

**Impact if something goes wrong:** high · **Verification confidence:** medium · `bf7be09998..143a99d178`

The Drizzle EQL migration rewriter, which exists as two copies (stash CLI and @cipherstash/wizard), stops replacing an in-place `ALTER COLUMN ... SET DATA TYPE <eql domain>` with ADD+DROP+RENAME. It now emits only `ADD COLUMN "<col>_encrypted"` and keeps the source column. Any skipped or unverified statement now fails closed: the CLI exits 1 and the wizard throws. This removes the base revision's worst failure, where the rewrite dropped plaintext or ciphertext on a populated table. The main new risk is that the generated SQL no longer matches the Drizzle schema that produced it. The schema still maps `<col>` to an encrypted domain, but after migrate the database column `<col>` is still plaintext and `<col>_encrypted` is a twin that neither the schema nor the snapshot knows about. Nothing in the change updates the schema, and no test covers the application-level state after the rewrite. A secondary issue is that `stash init` now swallows the new fail-closed exit and reports it as a drizzle-kit installation problem. Rewriter unit coverage is extensive, and the CI test jobs passed.

### Failure scenarios

**FS-1 · Rewritten migration leaves the Drizzle schema pointing at a still-plaintext column** (high impact, plausible)

- Trigger: A user or the wizard agent changes an existing Drizzle column in place to an encrypted type (e.g. `email: types.TextSearch('email')`). drizzle-kit emits `ALTER COLUMN "email" SET DATA TYPE eql_v3_text_search`, the sweep rewrites it, and the migration is applied. The wizard now defaults that prompt to yes.
- Mechanism: renderSafeAlter now emits only `ADD COLUMN "email_encrypted"` and keeps `email` as text. Nothing updates the TypeScript schema or the drizzle-kit snapshot, both of which still say `email` is the encrypted domain and know nothing of `email_encrypted`. At base, the DROP+RENAME left `email` as the encrypted domain, which matched the schema (on an empty table). The stack-drizzle custom type's toDriver returns a string, so writes through the schema can land in the text `email` column without a type error.
- Consequence: After migrate, the database and the application schema disagree. Inserts through the encrypted schema can store EQL envelopes as text in the plaintext source column, mixing them with existing plaintext rows. Reads of existing rows fail to decode or decrypt, and EQL query operators fail on a text column. The `email_encrypted` twin stays empty and unused. The next `drizzle-kit generate`, after the user renames the schema field to `email_encrypted` as the header comment advises, can emit an ADD of a column that already exists. In the wizard flow the run ends by printing 'Your data is now protected' while the data is still plaintext. Repair needs manual schema and migration surgery.
- Affects: packages/cli rewrite-migrations (stash eql migration --drizzle), packages/wizard rewrite-migrations + post-agent, Customer Drizzle migration directories and databases, Customer application code using @cipherstash/stack-drizzle column types
- Evidence: `packages/cli/src/commands/db/rewrite-migrations.ts:845-873`; `packages/cli/src/commands/db/rewrite-migrations.ts:799-874` (base); `packages/wizard/src/lib/post-agent.ts:82-113` (base); `packages/wizard/src/lib/post-agent.ts:59-101`; `packages/wizard/src/run.ts:235-290`; `packages/stack-drizzle/src/column.ts:163-176`; `skills/stash-drizzle/SKILL.md:450-461`
- Existing verification: Rewriter unit tests assert the emitted SQL is ADD COLUMN "<col>_encrypted" with no DROP/RENAME [exists_not_run]; CI 'Run Tests (Node 22/24/Bun)' and 'Run E2E Tests' jobs concluded success on head [ran_passed]
- Missing verification: No test or check covers the state after the rewrite: schema/snapshot vs database column types, or what the next `drizzle-kit generate` produces.; No evidence of what the wizard agent prompt tells the agent to do (remote prompt unavailable). It may already add `<col>_encrypted` twins instead of changing columns in place.
- Mitigation: Choose one approach and make it explicit. (a) When rewriting, also print a mandatory instruction to rename the schema field to `<col>_encrypted`, and fail or warn until the schema matches. (b) Have the rewriter or wizard update the schema/snapshot itself. (c) Do not offer to run migrate automatically in the wizard after a rewrite, and do not print 'data is now protected' in that case. Add a fixture test that runs generate→sweep→generate and asserts there is no drift.

**FS-2 · stash init reports the new fail-closed sweep exit as a drizzle-kit installation failure** (medium impact, observed in the code)

- Trigger: `stash init` on a Drizzle project whose migration directory contains any statement the sweep skips (source-unknown, target-exists, already-encrypted, an unrecognised form), or a sweep error.
- Mechanism: eqlMigrationCommand now throws CliExit(1) after writing the install migration (migration.ts:338-344). install-eql.ts catches every throw on the Drizzle path and logs 'Could not generate the EQL migration — check that drizzle-kit is installed and configured', telling the user to re-run `stash eql migration --drizzle`. It returns eqlMigrationPending unset, so init then reports 'EQL extension NOT installed', tells the user to run `stash eql install`, and exits 1.
- Consequence: The user is sent to fix the wrong thing. The install migration was in fact written, and re-running `stash eql migration --drizzle` scaffolds a further install migration (each run spawns `drizzle-kit generate --custom`), so the directory can accumulate duplicate EQL install migrations. Whether the bundle is idempotent was not checked. The unsafe sibling statements the sweep found are listed by the inner command but framed under the wrong headline.
- Affects: stash init (install-eql step, Drizzle path), packages/cli rewrite-migrations (stash eql migration --drizzle)
- Evidence: `packages/cli/src/commands/eql/migration.ts:289-344`; `packages/cli/src/commands/init/steps/install-eql.ts:125-143`; `packages/cli/src/commands/init/index.ts:149-160`; `packages/cli/src/commands/init/steps/__tests__/install-eql.test.ts:189-203`
- Existing verification: install-eql.test asserts a CliExit from eqlMigrationCommand is swallowed (drizzle-kit missing case); no test covers the sweep-abort case [exists_not_run]
- Missing verification: No test of init's message or end state when the sweep fails closed.; No check of whether repeated `stash eql migration --drizzle` runs produce duplicate install migrations, or whether those apply cleanly.
- Mitigation: Let the sweep abort reach init as its own outcome: re-throw the CliExit, or return eqlMigrationPending with a review warning. Do not reuse the drizzle-kit message. Add an install-eql test for it.

### Recommended controls

- Review whether add-only output is coherent with the Drizzle schema that produced the in-place ALTER, and decide how users are made to rename the schema field before deploying the app. (review_focus; FS-1)
- Add a fixture test: schema with an in-place encrypted column → drizzle-kit generate → sweep → generate again, asserting the outcome is documented and has no drift. (test; FS-1, VG-1)
- In the wizard, after a rewrite, do not default the migrate prompt to yes and do not print 'Your data is now protected' until the schema switch is done. (other; FS-1)
- Handle the sweep's CliExit in install-eql distinctly (re-throw, or mark the migration pending with a review warning) and cover it with a test. (test; FS-2, VG-2)
- Check skills/stash-drizzle/SKILL.md (usually co-changed with migration.ts, untouched here) so it describes what to do after the sweep adds `<col>_encrypted`. (documentation; FS-1)

### What this assessment could not see

- The wizard's agent prompt is fetched at run time and was not available, so it is unknown whether the agent changes columns in place (triggering FS-1) or adds `_encrypted` twins. FS-1 stays plausible_failure. How likely it is in the wizard flow is unknown.
- Test files were read selectively (the CLI migration tests, wizard post-agent tests, and the target-exists parts of the rewriter tests). The roughly 1,800-line rewriter test suites were skimmed by grep. I did not run tests myself. Test results rest only on job-level CI conclusions.
- Unchecked: whether the EQL v3 install bundle is idempotent when applied twice, and how drizzle-kit's next diff behaves after the add-only rewrite. The FS-1 and FS-2 consequences around drift and duplicate migrations are inferred, not demonstrated.
- The two rewriter copies were compared only at a high level. The in-sync test guards them, and a head-to-head diff shows only comment and import differences in the region inspected. Divergence between the two copies is not raised as a scenario.

_Inputs unavailable: dependency_graph, deployment_context._

_Advisory only. claude-code (headless) · claude-opus-5-5 · change-risk 1.0.0._
