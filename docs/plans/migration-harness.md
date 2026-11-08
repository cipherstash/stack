# Migration Harness implementation plan

Status: proposed. Source: [parent issue #1540](https://github.com/cipherstash/stack/issues/1540).
Architecture: [context ADR](../../e2e/migration-harness/docs/adr/0001-isolated-agent-migration-harness.md).

The Implementation Decisions are normative; user stories describe intent and defer to those decisions for defaults, outcomes and convergence. This plan incorporates review clarifications beyond the issue snapshot.

## Problem Statement

The Protect.js → Stack DynamoDB upgrade guide (docs/migration) is tied to compatibility tests, but nothing tests whether a reader can actually follow it. A guide can cite passing tests and still leave an agent or engineer stuck: a missing step, a pnpm-only command, an ambiguous instruction about boolean lookups or downcase columns. The only way we find out is when a customer, or an agent in a customer's repo, fails partway through an upgrade.

## Solution

A local Migration Harness that tests the guide by having agents follow it, and improves it in a loop. A Migrator agent upgrades a fresh copy of a small Protect.js Fixture App (DynamoDB and Postgres) using only the guide. A deterministic Oracle judges the result. An Editor agent revises the guide from the Oracle's failures and the Migrator's Friction Log. The loop repeats until Runs pass consistently with no actionable friction.

Vocabulary is defined in the harness CONTEXT.md under e2e/migration-harness: Fixture App, Run, Iteration, Legacy Data, Migrator, Oracle, Editor, Friction Log, Reference Migration, App Host, Mutation Data, Run slot, Loop, Fake Migrator and Needs-test List.

## User Stories

1. As a guide maintainer, I want to run one Run with a single command, so that I can see whether an agent can follow the current guide.
2. As a guide maintainer, I want every Run to start from a fresh copy of the Fixture App, so that Runs don't contaminate each other.
3. As a guide maintainer, I want Legacy Data written by the unmigrated Protect.js app before the Migrator starts, so that the guide's "no re-encryption" promise is tested against real legacy ciphertext.
4. As a guide maintainer, I want Legacy Data to cover the Fixture App's columns (text equality, downcase text equality, whole-number `number` equality, safe-range `bigint` equality, boolean equality, unindexed text) and a record already copied to Postgres, so that the guide's sections on those columns are exercised. JSON, dates, fractional numbers and the other exclusions below are not covered.
5. As a guide maintainer, I want the Oracle to check the Fixture App's public behaviour after migration, against both stores, on Legacy Data and fresh writes, so that a migration that compiles but breaks lookups fails.
6. As a guide maintainer, I want the Oracle to byte-compare every Legacy Data ciphertext and equality term against a snapshot taken at seeding, after the migrated app's read-only checks and before any mutation, so that a migration that re-encrypts on read fails and legitimate updates do not.
7. As a guide maintainer, I want the Oracle to check that `@cipherstash/protect`, `@cipherstash/protect-dynamodb`, `@cipherstash/schema` and the legacy `@cipherstash/protect-ffi` version are gone and the endpoint shim is removed, while allowing Stack's own `@cipherstash/protect-ffi`, so that a half-finished migration fails and a correct one passes.
8. As a guide maintainer, I want the Oracle to be deterministic with no agent involved, so that the verdicts can be trusted.
9. As a guide maintainer, I want the Migrator never to see the Oracle, so that it can't optimise for the checks instead of following the guide.
10. As a guide maintainer, I want the Migrator confined by an enforced filesystem boundary to its workspace, so that no tool, script or shell command can read the checkout, the Oracle, the Reference Migration or other Runs.
11. As a guide maintainer, I want an enforced network policy for every command the Migrator runs that permits only the package registry, CipherStash services and the Run's own Migrator stores, while the agent's model traffic goes through a host-side process whose credentials the sandbox never sees, so that gaps in this guide aren't papered over by other documentation and application code can't reach the model service or the Oracle's stores.
12. As a guide maintainer, I want the Migrator to have credentials and its own live stores seeded with Legacy Data, separate from the Oracle's, so that it can verify against data as the guide's step 6 asks without being able to disturb the Oracle's evidence.
13. As a guide maintainer, I want the Migrator's workspace to be a git repo whose first commit is the pristine app, so that the Migrator can diff and roll back, and the harness can capture its changes.
14. As a guide maintainer, I want the Fixture App to use npm, so that pnpm-only instructions in the guide show up as friction.
15. As a guide maintainer, I want the Migrator to record a Friction Log in a fixed template keyed by guide section, so that friction can be compared across Runs and Iterations.
16. As a guide maintainer, I want each Run capped by the configured time and turn limits, so that a stuck Migrator fails instead of burning budget.
17. As a guide maintainer, I want the Migrator on a mid-strength model by default, so that the guide is tested against the kind of agent likely to read it in a customer repo.
18. As a guide maintainer, I want to choose between published npm Stack and an in-tree tarball, resolved once per loop to an exact version or tarball digest, so that every Run in a loop tests the same Stack.
19. As a guide maintainer, I want every Run to leave a Run report with the Oracle results, diff, Friction Log and transcript, so that I can see why it failed.
20. As a guide maintainer, I want parallel Runs isolated by table and database, so that an Iteration can run several Runs at once.
21. As a guide maintainer, I want a hidden Reference Migration that passes every Oracle check, so that the Oracle is demonstrably passable; an individual failure still needs diagnosis before attribution to the guide.
22. As a guide maintainer, I want a self-test asserting that the Reference Migration passes, the pristine app fails only the migration layer, and targeted broken migrations each fail the expected check (missing downcase normalization on write, a stale boolean HMAC left after setActive, broken bigint serialization, ciphertext rewritten on read), so that I know the Oracle catches the guide's important failure modes.
23. As a guide maintainer, I want the self-test to use Fake Migrators and spend no tokens, so that I can run it whenever the harness changes.
24. As a guide maintainer, I want an Iteration to run several Runs, then one Editor pass over all their results, so that edits respond to patterns, not to one Run's noise.
25. As a guide maintainer, I want the Editor to change only the guide and a Needs-test List, so that each Iteration changes exactly one thing.
26. As a guide maintainer, I want the Editor forbidden from adding new compatibility claims, so that the guide never asserts something a test does not prove; the citation gate only proves cited names exist.
27. As a guide maintainer, I want claims with no test recorded on a Needs-test List, so that gaps in test coverage become work items, not invented citations.
28. As a guide maintainer, I want the guide's citation test run as a hard gate after every Editor edit, and the edit reverted if it fails, so that the loop can't break the guide's link to its tests.
29. As a guide maintainer, I want the Editor on a strong model by default, so that revisions are careful.
30. As a guide maintainer, I want the Loop to enforce the normative convergence and maximum-Iteration rules, so that recurring friction, or an Iteration that never really ran, can never count as converged.
31. As a guide maintainer, I want a loop summary of pass rates, new friction, kept and reverted edits and the Needs-test List, so that I can review the result before committing.
32. As a guide maintainer, I want nothing auto-committed, so that I review every guide change before it lands.
33. As a guide maintainer, I want skill drift the Editor notices reported rather than edited, so that customer-shipped skills change only through deliberate review.
34. As a repo contributor, I want the harness unreachable from `pnpm test` and absent from CI, so that it never spends tokens or needs credentials in ordinary test runs.
35. As a guide maintainer, I want the Migrator and Editor to be swappable commands with a defined contract, so that the pipeline can be tested with fakes and other agents can be tried later.
36. As a guide maintainer, I want every Run classified by the normative outcome rules below, so that diagnosis determines whether evidence warrants guide edits and infrastructure failures neither trigger edits nor count toward convergence.
37. As a guide maintainer, I want each Run to preserve the normative Run manifest, so that any Run can be reproduced.
38. As a guide maintainer, I want self-tests proving the Migrator cannot read the Oracle, the checkout or another Run's files, cannot reach another Run's or the Oracle's data even through an endpoint it is allowed to use, cannot reach unpermitted hosts or the model service, and cannot see model credentials, so that the isolation is demonstrated, not assumed.
39. As a guide maintainer, I want friction items reconciled by the normative Iteration rules, so that recurring friction stays open and missing Friction Logs cannot resolve it.
40. As a guide maintainer, I want an Iteration whose Run slots could not all finish because of exhausted infrastructure retries marked incomplete, so that it can never count as clean.
41. As a guide maintainer, I want the Oracle to install and execute the migrated app only inside a restricted process that can reach the npm registry, that Run's Oracle stores and CipherStash services, with assertions and snapshots kept outside it, so that migrated code can't read the Oracle, its snapshots or other Runs' credentials.
42. As a guide maintainer, I want every Run to produce a valid structured Friction Log, with an explicit empty list when there is no friction, so that a missing or malformed Friction Log fails the Run instead of reading as "no friction".

## Implementation Decisions

- Modules: Run driver (infra, workspace, seeding, Migrator invocation, Oracle, Run report); Oracle (behaviour, no-rewrite and static layers); Reference Migration plus Fake Migrators for the self-test; Migrator adapter (headless Claude in an enforced sandbox); Iteration driver with Editor adapter and citation gate; loop driver.
- The Fixture App and its glossary already exist in the harness directory. Before invoking a Migrator, remove the README sentence pointing it at a "harness acceptance command" and replace its fixed friction.md instruction with the schema and environment-named Friction Log output path. These are harness workspace preparation steps; the repository Fixture App remains unchanged in this planning PR.
- Infra. Store isolation is enforced by the stores themselves, not by naming, because a network policy can only allow or deny an endpoint, not a table on it.
  - **Oracle's stores**: each Run gets its own Oracle DynamoDB Local container, and its own database on a shared Oracle Postgres container. That database is cloned from an EQL v3 template, is owned by a per-Run Oracle role, and has CONNECT revoked from PUBLIC. No Migrator sandbox has a route to any of them. Only that Run's App Host may reach them, and only with that Run's role. The harness itself connects with admin credentials to seed and snapshot.
  - **Migrator's stores**: each Run gets its own DynamoDB Local container, so its endpoint holds no other Run's tables, and its own database on a shared Migrator Postgres container. That database is cloned from an EQL v3 template, is owned by a per-Run role, and has CONNECT revoked from PUBLIC, so the role can connect only to its own database. The Migrator gets only that role's credentials.
- Local endpoint topology: preserve the Fixture App's loopback-only store-host validation. Each sandbox has its own loopback forwarders to its assigned store endpoints. Enforce destination and port policy outside application control; never allow all host-loopback ports or expose Docker sockets. A container implementation must provide these namespace-local forwarders rather than passing container DNS names to the Fixture App. Shared Postgres endpoints still require per-Run database roles and CONNECT restrictions.
- Seeding: the pristine Fixture App writes Legacy Data and Mutation Data into both store sets before the Migrator starts. Mutation Data is excluded from the no-rewrite snapshot. The Oracle snapshots its own Legacy Data immediately after seeding.
- **App Host**: the Oracle never imports or runs migrated code in the harness process.
  - Installing the migrated workspace's dependencies, including any lifecycle scripts, and calling its createApp both happen in a per-Run App Host. That is a separate process in an OS-level sandbox of the same kind as the Migrator's.
  - Its filesystem view is a copy of the migrated workspace only.
  - Its network egress permits only the npm registry, CipherStash services and this Run's Oracle stores, with the Run's Oracle role.
  - It exposes the Fixture App README API to the harness over a narrow request/response channel (JSON over stdio), one call per message.
  - Assertions, snapshots, the Oracle source, the Reference Migration and all other Runs' credentials stay in the harness process, outside it.
  - Static checks read the workspace's files from the harness without executing them.
- Oracle order, against the Oracle's stores only, with every app call made through the App Host: (1) read-only behaviour checks on Legacy Data (get, every find*, getPostgres, findPostgres*); (2) no-rewrite comparison of every Legacy Data DynamoDB `__source`/`__hmac` and Postgres `c`/`hm` against the snapshot; (3) mutating behaviour checks (put, setActive, copyToPostgres, copyToDynamo) on Mutation Data, never on the snapshotted ones; (4) the migration layer.
- Migration layer: checks that hold only for a migrated app, so the pristine app is expected to fail every one.
  - Static: `@cipherstash/protect`, `@cipherstash/protect-dynamodb` and `@cipherstash/schema` are absent from imports, the manifest and the lockfile; `@cipherstash/protect-ffi` is allowed only at the version the resolved Stack depends on (the legacy 0.18.1 must be gone); the CS_CTS_HOST/CS_ZEROKMS_HOST shim is removed.
  - Stored-shape: after the migrated setActive on a Mutation Data record, the item has no `active__hmac` (guide step 5). This is asserted on the stored item, not through findActive: a correct migration implements findActive by decrypting and filtering, which a stale HMAC does not affect.
- Oracle pass means all layers pass.
- Isolation is enforced, not requested, with a host-side broker for the agent.
  - The agent process, which talks to the model service and holds its credentials, runs on the host, outside the sandbox.
  - Every command it executes (shell, node, npm, psql) runs inside an OS-level sandbox whose filesystem view is limited to the workspace and whose network egress permits only the npm registry, CipherStash services (CTS, ZeroKMS) and the Run's Migrator stores. The model service is not reachable from the sandbox, and model credentials are not in its environment or filesystem.
  - The agent's own file tools are restricted to the workspace by the agent runtime's enforced permission rules. Claude Code's sandboxed Bash plus deny rules is one way to build this; a container exec'd into by a host-side agent is another.
  - The tool allowlist stays as a further layer. The sandbox gets CS_* credentials and the Migrator stores' URLs and role credentials, and sees only the copied guide and the Fixture App.
- The Migrator is headless `claude -p`: Sonnet by default, `acceptEdits`, 40 minutes and 200 turns.
- Stack source: published npm, default range `^1.2.1`, or a tarball packed from the tree. Resolved once per loop (or per standalone Run or Iteration) to an exact version or tarball digest, which every Run installs.
- Run manifest: every Run report records the exact Stack version or tarball digest, guide content hash, Fixture App revision, model identifiers and agent configuration (allowlist, limits, sandbox policy).
- Failure classification: retain every observed failure in the Run report, but choose one primary outcome using the following precedence. A policy violation means an observed forbidden access attempt by Migrator tools, migrated code or lifecycle scripts, even when blocked and caught by the application.
  1. `isolation-violation`: a forbidden access attempt; terminal, non-infrastructure, never retried as infrastructure.
  2. `infrastructure`: verified harness provisioning or enforcement failure (containers, stores, credentials or inability to establish the sandbox), rather than an application's denied access or ordinary exception.
  3. `agent-limit`: time/turn limit, agent crash or non-zero agent exit.
  4. `install`: dependency installation failed after the Migrator finished.
  5. `invalid-friction-log`: missing or schema-invalid Friction Log after a finished Migrator, including when Oracle checks also fail.
  6. `behaviour`: Oracle failure after a finished Migrator.
  7. `friction-only`: Oracle passed and the valid Friction Log contains actionable friction.
  8. `pass`: Oracle passed, the Friction Log is valid and there is no actionable friction.
- Infrastructure Runs are excluded from Editor input and retried up to a configurable limit. An Iteration is complete only when every Run slot ends in a non-infrastructure outcome. Exhausted retries make it incomplete: no Editor pass, no clean result, a broken clean streak, and one Iteration consumed toward the maximum. Secondary failures remain visible regardless of primary outcome.
- Failure category is not attribution. Before changing the guide, the Editor must diagnose each candidate against a specific guide section and record the evidence and attribution in the Needs-test List: guide gap, Migrator error, harness defect, or unknown. Only a supported guide gap permits a guide edit. Other evidence remains recorded for human review; unknown attribution does not justify an edit. An invalid or absent Friction Log is not itself evidence of a guide gap.
- Command contract for swappable Migrator and Editor commands: input is the working directory plus environment variables naming the guide, workspace, store URLs (Migrator) or Iteration results directory (Editor), and the output paths; output is files at those paths (Friction Log for the Migrator; edited guide and Needs-test List for the Editor); exit 0 means finished, non-zero means the agent itself failed; the harness enforces the time limit by killing the process group and records `agent-limit`.
- The Friction Log is a structured file validated against a schema after the Migrator exits. It is a list of entries, each with a stable identifier (guide section slug plus a short issue slug), an actionable or informational flag, what was unclear, wrong or missing, and what the Migrator did instead. An empty list must be written explicitly. A missing or malformed file gives the `invalid-friction-log` outcome, even if the Oracle would pass.
- Friction is reconciled per complete Iteration. An identifier is open if any Run in that Iteration reports it as actionable. It is resolved only when a complete Iteration in which every slot produced a valid Friction Log reports it from no Run. A Run without a valid Friction Log never resolves anything by omission. Resolution needs no guide edit, so transient friction clears on a confirmation Iteration of the same revision.
- The Editor is headless `claude -p` on Opus by default. It gets the Oracle results, Friction Logs and diffs of non-infrastructure Runs inline, and exported transcripts to open when needed. An enforced read boundary exposes only the guide, Needs-test List and exported Iteration evidence; it denies the checkout, Oracle source, snapshots, Reference Migration, other workspaces and store credentials. The host-side model broker follows the same credential separation as the Migrator. Editor write access is limited to the guide and Needs-test List. Untrusted transcripts and diffs are evidence, never instructions. It may clarify, restructure and add procedural steps, and reuse existing claims with their existing citations; it may not add a new compatibility assertion, even one citing a real test. Any proposed claim goes on the Needs-test List for human review. Two mechanical gates run after every edit, and a failing edit is reverted: the guide citation test (cited names exist), and a citation-set check that rejects any citation absent from the previous revision, as a conservative restriction on the evidence the Editor may introduce; a new citation does not necessarily imply a new claim. Neither catches an uncited new claim or a new claim attached to an existing citation; that is caught by human review of the loop summary's guide diff before anything is committed.
- An Iteration is 3 Run slots in parallel by default, then one Editor pass. A clean Iteration is complete, has every Run slot passing (which requires a valid Friction Log from each), and has no actionable friction in any of those logs. The Editor makes no edit after a clean or incomplete Iteration. The loop stops when two consecutive Iterations are clean on the same guide revision (identical guide hash), or at 6 Iterations; both limits are configurable.
- Commands are local-only: `harness:run`, `harness:iterate`, `harness:loop`, `harness:selftest` in the e2e package. None is named after a turbo task. No workflow.

## Testing Decisions

- Test only through external behaviour: Run reports and Iteration results, never Oracle internals.
- Seam 1: a Run, with the Migrator as a swappable command. Fake Migrators drive the whole pipeline with no tokens: the Reference Migration (passes), no-op (passes behaviour and no-rewrite, fails the migration layer only), and targeted broken migrations that must each fail the named check: no downcase normalization on write (behaviour: case-insensitive lookup of a new record), stale boolean HMAC after setActive, with findActive correctly decrypting and filtering (migration layer: stored-shape check finds `active__hmac`), broken bigint serialization (behaviour: balance comes back as a non-string or wrong value), ciphertext rewritten on read (no-rewrite).
- Isolation self-tests: Fake Migrators must be denied, with the attempts recorded and primary outcome `isolation-violation`, when they try to:
  - read the checkout, the Oracle, the Reference Migration or another Run's workspace;
  - reach another Run's database through the allowed Migrator Postgres endpoint;
  - find any table but their own on their DynamoDB Local endpoint;
  - reach the Oracle's stores, a non-permitted host or the model service;
  - find model credentials in their environment or filesystem.
- App Host self-tests: fake migrations whose createApp tries to read the Oracle source, the snapshots, the checkout or another Run's workspace, or to reach another Run's Oracle stores or a non-permitted host, must be denied, with the attempts recorded, and the Run must have primary outcome `isolation-violation`. A fake migration whose dependency has a lifecycle script that does the same is denied too.
- Editor isolation self-tests must deny attempts to read the Reference Migration, Oracle source, snapshots, checkout or store credentials; a violating Editor edit is rejected and its denial recorded.
- Outcome precedence tests cover a blocked access plus a missing Friction Log, an absent Friction Log plus an Oracle failure, and a provisioning failure versus an application access denial. Attribution tests keep the guide unchanged for Migrator error, harness defect and unknown causes, and allow an evidence-backed guide-gap correction.
- Friction Log validation: a Fake Migrator that exits 0 with no Friction Log, and one that writes a malformed one, must give the `invalid-friction-log` outcome even when the migration itself is correct (the Reference Migration with no log).
- Seam 2: an Iteration, with the Editor as a swappable command. A fake Editor that adds a fabricated citation must be reverted; a clean edit must be kept. Infrastructure-classified Runs must be excluded from Editor input. Stop-condition tests use canned Iteration results, including recurring friction (never clean), two clean Iterations on different guide revisions (not converged), an Iteration with exhausted infrastructure retries (incomplete, breaks the streak), all Runs infrastructure-failed (incomplete, not clean), friction reported by one of three Runs (still open), transient friction absent from a full confirmation Iteration on the same revision (resolved), and open friction omitted by a Run with no valid Friction Log (still open, and the Iteration is not clean).
- A fake Editor that adds a real but previously uncited test citation must be reverted by the citation-set check. Uncited new claims and new claims attached to existing citations are left to human review of the guide diff; no test claims to catch them.
- Tests that need credentials and Docker are gated like the compat suite.
- Prior art: the credential-gated compat and crossover vitest suites in the e2e package, and the guide citation test (protect-upgrade-guide) used as the Editor gate.

## Out of Scope

- Running the harness in CI.
- Upgrading an EQL v2 Postgres database; the Fixture App's Postgres is already EQL v3.
- JSON (`dataType('json')`) columns, date columns, lock contexts, nested attributes, and index kinds beyond equality.
- Real AWS DynamoDB; DynamoDB Local only.
- The Editor editing skills, the Fixture App, the Oracle or the compat tests.
- Auto-committing guide changes or opening PRs.
- Other upgrade guides; the harness targets this one guide first.

## Further Notes

Tickets: #1534, #1535, #1536, #1537, #1538, #1539.

Review reconciliation: this plan intentionally clarifies "no new friction" as "no actionable friction", matching the clean-Iteration rule. The Reference Migration proves passability rather than attribution; citation-set restrictions do not establish claim semantics. Remaining changes resolve the reported terminology, isolation, topology, outcome and attribution gaps.
