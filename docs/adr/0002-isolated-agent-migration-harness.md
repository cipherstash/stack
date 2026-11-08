---
status: proposed
---

# Test migration guide usability with isolated agent Runs

Compatibility tests prove supported encryption operations, but do not show whether
an engineer or agent can follow the migration guide. We will use a local Migration
Harness with fresh legacy applications, isolated Migrators, a deterministic Oracle,
and an Editor that revises only the guide and a needs-test list. This separates
usability evidence from compatibility evidence and keeps agent-written application
code outside the process that holds the assertions and snapshots.

This ADR records the implementation contract from [the parent spec](https://github.com/cipherstash/stack/issues/1540),
reviewed at its 2026-11-06 revision. It is proposed for approval through this PR;
implementation follows in stacked PRs. The requirements below are retained so an
implementer does not depend on a mutable issue body. Domain terms follow the
[Migration Harness glossary](../../e2e/migration-harness/CONTEXT.md).

## Considered Options

- Existing compatibility and citation tests alone: retain them as evidence for
  claims, but they cannot reveal missing instructions or agent confusion.
- One agent that migrates, judges, and edits: rejected because it could alter its
  own evidence or adapt directly to hidden assertions.
- A shared application execution process and stores: rejected because migrated
  code and dependency scripts could read assertions or disturb other Runs.
- CI execution: deferred because this experiment requires live credentials,
  Docker and model budget; ordinary repository tests must remain independent.

## Consequences

The harness requires enforced filesystem and network isolation, separate stores,
and a restricted App Host even for dependency installation. A Reference Migration
proves feasibility, not that every failure is caused by the guide. Convergence is
bounded evidence about this fixture and guide revision, not proof for arbitrary
customer applications. Citation gates cannot validate the meaning of a claim;
human review of the resulting guide diff remains required.

The acceptance seams are whole Run reports and whole Iteration results, with
swappable agent commands. The existing fixture API is the App Host protocol
boundary. No public SDK API or encrypted payload format changes are required.

## Implementation Contract

## Problem Statement

The Protect.js → Stack DynamoDB upgrade guide (docs/migration) is tied to compatibility tests, but nothing tests whether a reader can actually follow it. A guide can cite passing tests and still leave an agent or engineer stuck: a missing step, a pnpm-only command, an ambiguous instruction about boolean lookups or downcase columns. The only way we find out is when a customer, or an agent in a customer's repo, fails partway through an upgrade.

## Solution

A local Migration Harness that tests the guide by having agents follow it, and improves it in a loop. A Migrator agent upgrades a fresh copy of a small Protect.js Fixture App (DynamoDB and Postgres) using only the guide. A deterministic Oracle judges the result. An Editor agent revises the guide from the Oracle's failures and the Migrator's Friction Log. The loop repeats until Runs pass consistently with no actionable friction.

Vocabulary is defined in the harness CONTEXT.md under e2e/migration-harness: Fixture App, Run, Iteration, Legacy Data, Migrator, Oracle, Editor, Friction Log, Reference Migration.

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
16. As a guide maintainer, I want each Run capped at 40 minutes and 200 turns, so that a stuck Migrator fails instead of burning budget.
17. As a guide maintainer, I want the Migrator on a mid-strength model by default, so that the guide is tested against the kind of agent likely to read it in a customer repo.
18. As a guide maintainer, I want to choose between published npm Stack and an in-tree tarball, resolved once per loop to an exact version or tarball digest, so that every Run in a loop tests the same Stack.
19. As a guide maintainer, I want every Run to leave a report with the Oracle results, diff, Friction Log and transcript, so that I can see why it failed.
20. As a guide maintainer, I want parallel Runs isolated by table and database, so that an Iteration can run several Runs at once.
21. As a guide maintainer, I want a hidden Reference Migration that passes every Oracle check, so that the Oracle is demonstrably passable; an individual failure still needs diagnosis before attribution to the guide.
22. As a guide maintainer, I want a self-test asserting that the Reference Migration passes, the pristine app fails only the migration layer, and targeted broken migrations each fail the expected check (missing downcase normalization on write, a stale boolean HMAC left after setActive, broken bigint serialization, ciphertext rewritten on read), so that I know the Oracle catches the guide's important failure modes.
23. As a guide maintainer, I want the self-test to use fake Migrators and spend no tokens, so that I can run it whenever the harness changes.
24. As a guide maintainer, I want an Iteration to run several Runs, then one Editor pass over all their results, so that edits respond to patterns, not to one Run's noise.
25. As a guide maintainer, I want the Editor to change only the guide and a needs-test list, so that each Iteration changes exactly one thing.
26. As a guide maintainer, I want the Editor forbidden from adding new compatibility claims, so that the guide never asserts something a test does not prove; the citation gate only proves cited names exist.
27. As a guide maintainer, I want claims with no test recorded on a needs-test list, so that gaps in test coverage become work items, not invented citations.
28. As a guide maintainer, I want the guide's citation test run as a hard gate after every Editor edit, and the edit reverted if it fails, so that the loop can't break the guide's link to its tests.
29. As a guide maintainer, I want the Editor on a strong model by default, so that revisions are careful.
30. As a guide maintainer, I want the loop to stop after two consecutive clean Iterations on the same guide revision, or a maximum of six, where clean means every configured Run slot finished and passed and no Run reported actionable friction, so that recurring friction, or an Iteration that never really ran, can never count as converged.
31. As a guide maintainer, I want a loop summary of pass rates, new friction, kept and reverted edits and the needs-test list, so that I can review the result before committing.
32. As a guide maintainer, I want nothing auto-committed, so that I review every guide change before it lands.
33. As a guide maintainer, I want skill drift the Editor notices reported rather than edited, so that customer-shipped skills change only through deliberate review.
34. As a repo contributor, I want the harness unreachable from `pnpm test` and absent from CI, so that it never spends tokens or needs credentials in ordinary test runs.
35. As a guide maintainer, I want the Migrator and Editor to be swappable commands with a defined contract, so that the pipeline can be tested with fakes and other agents can be tried later.
36. As a guide maintainer, I want every Run failure classified as infrastructure, dependency installation, agent limit, migration behaviour or guide friction, so that only guide-attributable failures drive edits and infrastructure failures neither trigger edits nor count toward convergence.
37. As a guide maintainer, I want each Run to record the Stack version or tarball digest, guide hash, fixture revision, model identifier and agent configuration, so that any Run can be reproduced.
38. As a guide maintainer, I want self-tests proving the Migrator cannot read the Oracle, the checkout or another Run's files, cannot reach another Run's or the Oracle's data even through an endpoint it is allowed to use, cannot reach unpermitted hosts or the model service, and cannot see model credentials, so that the isolation is demonstrated, not assumed.
39. As a guide maintainer, I want each friction item to carry a stable identifier and to be reconciled across a whole Iteration, so that an item stays open while any Run reports it and closes when a complete Iteration reports it from no Run, with or without a guide edit.
40. As a guide maintainer, I want an Iteration whose Run slots could not all finish because of exhausted infrastructure retries marked incomplete, so that it can never count as clean.
41. As a guide maintainer, I want the Oracle to install and execute the migrated app only inside a restricted process that can reach just that Run's Oracle stores and CipherStash services, with assertions and snapshots kept outside it, so that migrated code can't read the Oracle, its snapshots or other Runs' credentials.
42. As a guide maintainer, I want every Run to produce a valid structured Friction Log, with an explicit empty list when there is no friction, so that a missing or malformed report fails the Run instead of reading as "no friction".

## Implementation Decisions

- Modules: Run driver (infra, workspace, seeding, Migrator invocation, Oracle, report); Oracle (behaviour, no-rewrite and static layers); Reference Migration plus fake Migrators for the self-test; Migrator adapter (headless Claude in an enforced sandbox); Iteration driver with Editor adapter and citation gate; loop driver.
- The Fixture App and its glossary already exist in the harness directory. One README sentence pointing the Migrator at a "harness acceptance command" is removed.
- Infra. Store isolation is enforced by the stores themselves, not by naming, because a network policy can only allow or deny an endpoint, not a table on it.
  - **Oracle's stores**: each Run gets its own Oracle DynamoDB Local container, and its own database on a shared Oracle Postgres container. That database is cloned from an EQL v3 template, is owned by a per-Run Oracle role, and has CONNECT revoked from PUBLIC. No Migrator sandbox has a route to any of them. Only that Run's App Host may reach them, and only with that Run's role. The harness itself connects with admin credentials to seed and snapshot.
  - **Migrator's stores**: each Run gets its own DynamoDB Local container, so its endpoint holds no other Run's tables, and its own database on a shared Migrator Postgres container. That database is cloned from an EQL v3 template, is owned by a per-Run role, and has CONNECT revoked from PUBLIC, so the role can connect only to its own database. The Migrator gets only that role's credentials.
- Seeding: the pristine Fixture App writes Legacy Data into both store sets before the Migrator starts. The Oracle snapshots its own Legacy Data immediately after seeding.
- **App Host**: the Oracle never imports or runs migrated code in the harness process.
  - Installing the migrated workspace's dependencies, including any lifecycle scripts, and calling its createApp both happen in a per-Run App Host. That is a separate process in an OS-level sandbox of the same kind as the Migrator's.
  - Its filesystem view is a copy of the migrated workspace only.
  - Its network egress permits only the npm registry, CipherStash services and this Run's Oracle stores, with the Run's Oracle role.
  - It exposes the Fixture README API to the harness over a narrow request/response channel (JSON over stdio), one call per message.
  - Assertions, snapshots, the Oracle source, the Reference Migration and all other Runs' credentials stay in the harness process, outside it.
  - Static checks read the workspace's files from the harness without executing them.
- Oracle order, against the Oracle's stores only, with every app call made through the App Host: (1) read-only behaviour checks on Legacy Data (get, every find*, getPostgres, findPostgres*); (2) no-rewrite comparison of every Legacy Data DynamoDB `__source`/`__hmac` and Postgres `c`/`hm` against the snapshot; (3) mutating behaviour checks (put, setActive, copyToPostgres, copyToDynamo) on separate records seeded for that purpose, never on the snapshotted ones; (4) the migration layer.
- Migration layer: checks that hold only for a migrated app, so the pristine app is expected to fail every one.
  - Static: `@cipherstash/protect`, `@cipherstash/protect-dynamodb` and `@cipherstash/schema` are absent from imports, the manifest and the lockfile; `@cipherstash/protect-ffi` is allowed only at the version the resolved Stack depends on (the legacy 0.18.1 must be gone); the CS_CTS_HOST/CS_ZEROKMS_HOST shim is removed.
  - Stored-shape: after the migrated setActive on a reserved legacy record, the item has no `active__hmac` (guide step 5). This is asserted on the stored item, not through findActive: a correct migration implements findActive by decrypting and filtering, which a stale HMAC does not affect.
- Oracle pass means all layers pass.
- Isolation is enforced, not requested, with a host-side broker for the agent.
  - The agent process, which talks to the model service and holds its credentials, runs on the host, outside the sandbox.
  - Every command it executes (shell, node, npm, psql) runs inside an OS-level sandbox whose filesystem view is limited to the workspace and whose network egress permits only the npm registry, CipherStash services (CTS, ZeroKMS) and the Run's Migrator stores. The model service is not reachable from the sandbox, and model credentials are not in its environment or filesystem.
  - The agent's own file tools are restricted to the workspace by the agent runtime's enforced permission rules. Claude Code's sandboxed Bash plus deny rules is one way to build this; a container exec'd into by a host-side agent is another.
  - The tool allowlist stays as a further layer. The sandbox gets CS_* credentials and the Migrator stores' URLs and role credentials, and sees only the copied guide and the Fixture App.
- The Migrator is headless `claude -p`: Sonnet by default, `acceptEdits`, 40 minutes and 200 turns.
- Stack source: published npm, default range `^1.2.1`, or a tarball packed from the tree. Resolved once per loop (or per standalone Run or Iteration) to an exact version or tarball digest, which every Run installs.
- Run manifest: every Run report records the exact Stack version or tarball digest, guide content hash, fixture revision, model identifiers and agent configuration (allowlist, limits, sandbox policy).
- Failure classification: every Run report has one outcome — pass, or a failure category: `infrastructure` (containers, stores, credentials, sandbox), `install` (dependency installation), `agent-limit` (time or turn limit, agent crash), `report` (the Migrator exited without a valid Friction Log), `behaviour` (Oracle failure with the Migrator finished), or `friction-only` (Oracle passed, actionable friction recorded). `report` is a failed, non-infrastructure outcome: the slot fails and the Iteration cannot be clean. `infrastructure` Runs are excluded from Editor input; the Iteration reruns them up to a retry limit. An Iteration is **complete** only when every configured Run slot ends in a non-infrastructure outcome. If retries are exhausted, the Iteration is **incomplete**: the Editor does not run, it is not clean, it breaks the consecutive-clean streak, and it counts toward the maximum.
- Command contract for swappable Migrator and Editor commands: input is the working directory plus environment variables naming the guide, workspace, store URLs (Migrator) or Iteration results directory (Editor), and the output paths; output is files at those paths (Friction Log for the Migrator; edited guide and needs-test list for the Editor); exit 0 means finished, non-zero means the agent itself failed; the harness enforces the time limit by killing the process group and records `agent-limit`.
- The Friction Log is a structured file validated against a schema after the Migrator exits. It is a list of entries, each with a stable identifier (guide section slug plus a short issue slug), an actionable or informational flag, what was unclear, wrong or missing, and what the Migrator did instead. An empty list must be written explicitly. A missing or malformed file gives the `report` outcome, even if the Oracle would pass.
- Friction is reconciled per complete Iteration. An identifier is open if any Run in that Iteration reports it as actionable. It is resolved only when a complete Iteration in which every slot produced a valid Friction Log reports it from no Run. A Run without a valid report never resolves anything by omission. Resolution needs no guide edit, so transient friction clears on a confirmation Iteration of the same revision.
- The Editor is headless `claude -p` on Opus by default. It gets the Oracle reports, Friction Logs and diffs of non-infrastructure Runs inline, and transcript paths to open when needed. It may write only the guide and the needs-test list. It may clarify, restructure and add procedural steps, and reuse existing claims with their existing citations; it may not add a new compatibility assertion, even one citing a real test. Any proposed claim goes on the needs-test list for human review. Two mechanical gates run after every edit, and a failing edit is reverted: the guide citation test (cited names exist), and a citation-set check that rejects any citation absent from the previous revision, as a conservative restriction on the evidence the Editor may introduce; a new citation does not necessarily imply a new claim. Neither catches an uncited new claim or a new claim attached to an existing citation; that is caught by human review of the loop summary's guide diff before anything is committed.
- An Iteration is 3 Run slots in parallel by default, then one Editor pass. A clean Iteration is complete, has every Run slot passing (which requires a valid Friction Log from each), and has no actionable friction in any of those logs. The Editor makes no edit after a clean or incomplete Iteration. The loop stops when two consecutive Iterations are clean on the same guide revision (identical guide hash), or at 6 Iterations; both limits are configurable.
- Commands are local-only: `harness:run`, `harness:iterate`, `harness:loop`, `harness:selftest` in the e2e package. None is named after a turbo task. No workflow.

## Testing Decisions

- Test only through external behaviour: Run reports and Iteration results, never Oracle internals.
- Seam 1: a Run, with the Migrator as a swappable command. Fake Migrators drive the whole pipeline with no tokens: the Reference Migration (passes), no-op (passes behaviour and no-rewrite, fails the migration layer only), and targeted broken migrations that must each fail the named check: no downcase normalization on write (behaviour: case-insensitive lookup of a new record), stale boolean HMAC after setActive, with findActive correctly decrypting and filtering (migration layer: stored-shape check finds `active__hmac`), broken bigint serialization (behaviour: balance comes back as a non-string or wrong value), ciphertext rewritten on read (no-rewrite).
- Isolation self-tests: fake Migrators must be denied, with the attempts recorded, when they try to:
  - read the checkout, the Oracle, the Reference Migration or another Run's workspace;
  - reach another Run's database through the allowed Migrator Postgres endpoint;
  - find any table but their own on their DynamoDB Local endpoint;
  - reach the Oracle's stores, a non-permitted host or the model service;
  - find model credentials in their environment or filesystem.
- App Host self-tests: fake migrations whose createApp tries to read the Oracle source, the snapshots, the checkout or another Run's workspace, or to reach another Run's Oracle stores or a non-permitted host, must be denied, with the attempts recorded, and the Run must fail. A fake migration whose dependency has a lifecycle script that does the same is denied too.
- Friction Log validation: a fake Migrator that exits 0 with no Friction Log, and one that writes a malformed one, must give the `report` outcome even when the migration itself is correct (the Reference Migration with no log).
- Seam 2: an Iteration, with the Editor as a swappable command. A fake Editor that adds a fabricated citation must be reverted; a clean edit must be kept. Infrastructure-classified Runs must be excluded from Editor input. Stop-condition tests use canned Iteration results, including recurring friction (never clean), two clean Iterations on different guide revisions (not converged), an Iteration with exhausted infrastructure retries (incomplete, breaks the streak), all Runs infrastructure-failed (incomplete, not clean), friction reported by one of three Runs (still open), transient friction absent from a full confirmation Iteration on the same revision (resolved), and open friction omitted by a Run with no valid report (still open, and the Iteration is not clean).
- A fake Editor that adds a real but previously uncited test citation must be reverted by the citation-set check. Uncited new claims are left to human review of the guide diff; no test claims to catch them.
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
