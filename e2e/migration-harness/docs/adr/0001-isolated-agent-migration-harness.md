---
status: proposed
date: 2026-11-09
---

# Deliver the Protect/EQL v2 to Stack/EQL v3 guide and verify it with isolated agent Runs

Compatibility tests establish supported encryption operations but cannot show
whether a reader can follow the Protect.js upgrade guide. We will use a local
Migration Harness: a Migrator upgrades a fresh Fixture App, a deterministic Oracle
checks it through a restricted App Host, and an Editor revises the guide from
Iteration Results. This ADR is the authoritative architecture and implementation
contract for [epic #1540](https://github.com/cipherstash/stack/issues/1540),
using the [context glossary](../../CONTEXT.md). Status remains proposed pending review.
The full implementation contract remains in this ADR at the maintainer's direction,
as an explicit exception to the usual short ADR format.

Keep agent execution separate from the process holding assertions and snapshots.
Migrators and App Hosts receive separate Store Sets and enforced filesystem
and network boundaries. The Editor sees Iteration Results but cannot
read Protected Resources. Dependency lifecycle
scripts execute within the same restrictions as migrated application code.

Test at whole Run and Iteration boundaries using swappable agent commands. Preserve
Legacy Data for no-rewrite checks and use distinct Mutation Data for updates.
A Reference Migration proves the Oracle is passable; failures still require
diagnosis before guide edits. Require valid Friction Logs and two consecutive
Clean Iterations on the same guide revision before declaring convergence.

## Considered Options

- Compatibility and citation tests alone miss unclear or absent instructions.
- Having one agent migrate, judge and edit lets it adapt to its own assertions.
- Shared execution and stores expose Protected Resources and permit Run interference.
- Real agent execution in CI is out of scope. Deterministic credentialed
  compatibility and Fake Migrator tests are permitted by the priority amendment.
  The maintainer requested a dedicated credential-free CI workflow for self-tests
  and Docker capability probes; ordinary tests still need neither model budget,
  live credentials nor this harness's Docker environment.

## Consequences

Per-process loopback forwarding preserves the Fixture App's loopback-only endpoint rule.
Convergence provides evidence for this Fixture App and guide revision only.
Citation gates validate reference names, not claims; human review of guide changes
remains required. The requirements and acceptance contract below form part of
this decision and guide the stacked implementation PRs.

## Priority amendment: v2 to v3 for both stores

Amended 2026-11-10 at the maintainer's direction. The first deliverable is a
tested Protect/EQL v2 to Stack/EQL v3 migration guide covering both DynamoDB and
Postgres. Here v2 and v3 name the EQL generations, not npm package majors:
the starting client is Protect.js 10.2.1 and the target is Stack 1.x's v3 API.
Pin the tested target release or in-tree digest in verification evidence.
EQL v4 migration work follows this deliverable and is not a prerequisite.

The existing DynamoDB guide, compatibility suites and harness remain useful.
Their Postgres coverage starts with EQL v3 columns populated from DynamoDB
attributes; it does not establish an upgrade of a Protect-written EQL v2
Postgres database. PRs #1496 and #1497 cover migration to v4, not this missing
v2-to-v3 path. This amendment supersedes the former exclusion of Postgres
v2-to-v3 upgrades and the former single-DynamoDB-guide scope.

### Problem Statement

A Protect user needs instructions for upgrading an existing application and
its encrypted data to Stack's v3 API on either store. A DynamoDB-to-Postgres
copy example cannot tell a Postgres user how to migrate existing v2 columns,
queries, indexes and application dependencies. Passing harness self-tests
alone also cannot establish that a customer can complete the guide.

### Solution

Deliver one v2-to-v3 guide with common preparation and explicit DynamoDB and
Postgres procedures, backed by executable before/after examples and live
compatibility tests. Preserve the existing DynamoDB instructions and citations
while adding the missing Postgres procedure. Complete this guide before
resuming v4 migration work. Then extend the existing Migration Harness to
test both procedures through its existing Run and Iteration contracts.

### User Stories

These stories extend, rather than renumber, the 42 harness stories below.

43. As a Protect user, I want the guide to distinguish package versions from EQL generations, so that I install the intended Stack release.
44. As a Protect user, I want a shared preparation checklist and a procedure for my store, so that I can upgrade without following unrelated cross-store instructions.
45. As a DynamoDB user, I want to read and query existing Protect-written items with Stack and write new items beside them, so that I can verify the upgrade before deployment.
46. As a DynamoDB user, I want explicit treatment of boolean lookups, downcase normalization, bigint serialization and legacy JSON, so that compatibility exceptions are not hidden by a blanket no-re-encryption claim.
47. As a Postgres user, I want an example starting with actual Protect-written EQL v2 columns, so that the procedure matches my existing database.
48. As a Postgres user, I want tested mappings from supported v2 columns and queries to v3 domains and queries, so that changing the client does not silently change query results.
49. As a Postgres user, I want to know which stored ciphertext and search terms can be retained and which require conversion, so that I do not perform unnecessary or unsafe rewrites.
50. As a Postgres user, I want installation, data conversion, index creation, application cutover and verification instructions, so that I can execute the whole migration.
51. As a Postgres user, I want an explicit write-maintenance window and rollback boundary, so that concurrent writes and post-cutover changes cannot silently invalidate recovery.
52. As a Protect user, I want unsupported types, query capabilities and deployment patterns listed before mutation, so that I can stop before damaging data or losing required queries.
53. As a guide maintainer, I want each compatibility claim tied to a passing live test and reproducible example, so that the guide describes demonstrated behaviour.
54. As a guide maintainer, I want the Postgres procedure checked independently of the agent Loop, so that finishing harness automation is not a prerequisite for delivering the guide.
55. As a guide maintainer, I want the Oracle to check a migration starting from v2 Postgres columns, so that an already-v3 Fixture App cannot produce false confidence.
56. As a guide maintainer, I want independent guide-only Runs for both store procedures, so that success on DynamoDB cannot conceal Postgres friction.
57. As a guide maintainer, I want v4 work explicitly deferred until the v2-to-v3 guide is complete, so that migration targets and their evidence remain separate.

### Implementation Decisions

- Guide scope: common package, credential and schema preparation, followed by
  separate store procedures. Cross-store copying remains optional and is not
  evidence for an existing Postgres database upgrade.
- Preserve the existing DynamoDB coverage and its documented exceptions.
  Initially demonstrate Postgres text equality, integer-valued number equality
  and storage-only text, matching the existing cross-store evidence. Record
  the exact legacy declarations and supported value ranges. Inventory boolean,
  normalization, bigint, JSON, dates, fractional numbers, grouped fields,
  lock contexts, range/order and text-search capabilities explicitly; a
  capability without a passing migration example is unsupported by this
  first procedure, not implicitly safe. Do not drop such columns or indexes.
- The Postgres example begins with real Protect.js writes to EQL v2 columns
  and verifies the legacy application's reads and queries before migration.
  Install EQL v3 alongside the legacy setup and build separate target columns.
  Establish the conversion from actual stored payloads in live tests; do not
  assume that a cast or changing a version field is sufficient. Preserve
  ciphertext/search-term bytes where the test proves it is valid. Any required
  re-encryption must be stated per supported mapping and tested explicitly.
- Use an explicit write-maintenance window for this first Postgres procedure.
  Preserve source columns and data while populating and verifying target
  columns, rebuilding required indexes and switching application reads and
  writes. Verify row counts, plaintext, query result sets and fresh writes.
  Demonstrate rollback before writes resume. After target-only writes resume,
  do not promise rollback by renaming old columns; document the need to
  reconcile those writes. Zero-downtime dual-writing is outside this delivery.
- Follow the system-wide durable-data ADR: installation must preserve data;
  capture, rebuild and verify derived indexes, and refuse unsupported customer
  dependencies before mutation. The example must not drop a schema with
  CASCADE as a substitute for migrating customer columns.
- Keep #1534–#1536 and their existing Fixture App acceptance scope intact.
  Their original Store Set provisioning, Oracle ordering and no-rewrite checks
  below describe the DynamoDB/cross-store baseline. A separate extension adds
  a Postgres-v2 Fixture App starting state, Reference Migration and Broken
  Migrations. Provision v2 for that starting state; never seed into v3 and call
  it a v2 upgrade. Each Run identifies its store procedure and source/target
  EQL generations in its Run Manifest.
- The Postgres extension applies the migrated application's database migration
  through the restricted App Host to independently seeded Oracle Stores before
  checking them. Migrator Stores remain separate. Compare source bytes and
  verified retained ciphertext/search terms across conversion; permitted new
  envelopes, target columns and indexes are not themselves no-rewrite failures.
  Unexpected ciphertext rewriting for a mapping proven to retain bytes fails.
- Maintain the existing isolation, evidence export and Editor gates. An
  Iteration evaluates one store procedure; its guide revision and procedure
  identity must match before Clean Iterations count toward convergence. Combined convergence requires both procedures to meet their clean-Iteration
  criterion against the same final guide hash, whether or not the Editor made
  edits. Any guide edit invalidates convergence evidence for the previous hash.
- Delivery order: finish the two tested guide procedures first. Extend the
  Postgres harness and complete #1537–#1539 afterwards. Adapter work may reuse
  existing seams, but is not a blocker for shipping the tested guide. No v4
  package, codec, payload or SDK adoption is required for this workstream.

### Testing Decisions

- Migration correctness uses the existing live compatibility test boundary:
  real legacy writes, the documented migration procedure, Stack reads/writes
  and actual database queries. Assertions compare externally observable
  results and stored bytes where preservation is claimed, not helper internals.
- The Postgres example is executable independently, then exercised by the live
  suite with a disposable database and real encryption. Cover the supported
  mappings end to end, fresh writes, index definitions and use on a suitable
  dataset, the declared rollback window, and refusal of unsupported inputs
  before mutation. A skipped credentialed suite is not migration evidence.
- Keep the guide citation gate and extend it to the Postgres evidence. A test
  name existing is necessary but insufficient: review that the cited test
  actually proves the associated claim. List all exclusions in the guide.
- Harness usability stays at Run Reports and Iteration Results. A correct
  Postgres Reference Migration passes; a no-op, a conversion losing rows, an
  incorrect column/query mapping, a missing required index and an unexpected
  ciphertext rewrite each fail a named observable Oracle check. Retain the
  existing DynamoDB self-tests unchanged.
- Use credentialed CI for deterministic compatibility and Fake Migrator
  integration tests; keep real Migrators, Editors and Loops opt-in and outside
  CI. This supersedes the original blanket CI exclusion below, following the
  maintainer's full-CI request for #1535/#1536.

### Out of Scope

- Migration to EQL v4, replacing the encryption engine, or taking v4 PRs as a
  dependency of the v2-to-v3 guide.
- Universal no-re-encryption claims or support inferred from another store.
- Production backfill services, zero-downtime dual-write orchestration and
  every ORM-specific migration workflow. The first Postgres procedure uses
  direct SQL and the Stack client.
- Real AWS coverage remains excluded from the harness; distinguish DynamoDB
  Local checks from deployed AWS request, GSI and operational guarantees.

### Further Notes

The guide is ready when both supported procedures have executable examples,
passing live CI, accurate citations, explicit exclusions and reviewed cutover
instructions. Agent convergence is a subsequent guide-usability milestone,
not a substitute for this evidence or a gate on first guide delivery.
The epic tracks these milestones; the full contract remains in this ADR.
Guide delivery is tracked by #1604 (DynamoDB) and #1603 (Postgres), which can
start from PR #1519 without waiting for the agent harness. #1605 extends the
Postgres Run after #1603 and #1536. Existing #1534–#1536 acceptance remains the
DynamoDB/cross-store baseline; #1537–#1539 integrate the two procedures for the
subsequent usability milestone.

## Problem Statement

The Protect.js → Stack DynamoDB upgrade guide (docs/migration) is tied to compatibility tests, but nothing tests whether a reader can actually follow it. A guide can cite passing tests and still leave an agent or engineer stuck: a missing step, a pnpm-only command, an ambiguous instruction about boolean lookups or downcase columns. The only way we find out is when a customer, or an agent in a customer's repo, fails partway through an upgrade.

## Solution

A local Migration Harness that tests the guide by having agents follow it, and improves it in a Loop. A Migrator agent upgrades a fresh copy of a small Protect.js Fixture App (DynamoDB and Postgres) using only the guide. A deterministic Oracle judges the result. An Editor agent revises the guide from the Oracle's failures and the Migrator's Friction Log. The Loop repeats until Runs pass consistently with no actionable friction.

Use the [Migration Harness glossary](../../CONTEXT.md) for domain vocabulary.

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
10. As a guide maintainer, I want the Migrator confined by an enforced filesystem boundary to its workspace, so that no tool, script or shell command can read Protected Resources.
11. As a guide maintainer, I want an enforced network policy for every command the Migrator runs that permits only the package registry, CipherStash services and the Run's own Migrator Stores, while the agent's model traffic goes through a host-side process whose credentials the Migrator Environment never sees, so that gaps in this guide aren't papered over by other documentation and application code can't reach the model service or Oracle Stores.
12. As a guide maintainer, I want the Migrator to have credentials and Migrator Stores seeded with Legacy Data, separate from Oracle Stores, so that it can verify against data as the guide's step 6 asks without being able to disturb the Oracle's evidence.
13. As a guide maintainer, I want the Migrator's workspace to be a git repo whose first commit is the unmigrated Fixture App, so that the Migrator can diff and roll back, and the harness can capture its changes.
14. As a guide maintainer, I want the Fixture App to use npm, so that pnpm-only instructions in the guide show up as friction.
15. As a guide maintainer, I want the Migrator to record a Friction Log in a fixed template keyed by guide section, so that friction can be compared across Runs and Iterations.
16. As a guide maintainer, I want each Run capped by the configured time and turn limits, so that a stuck Migrator fails instead of burning budget.
17. As a guide maintainer, I want the Migrator on a mid-strength model by default, so that the guide is tested against the kind of agent likely to read it in a customer repo.
18. As a guide maintainer, I want to choose between published npm Stack and an in-tree tarball, resolved once per Loop to an exact version or tarball digest, so that every Run in a Loop tests the same Stack.
19. As a guide maintainer, I want every Run to leave a Run Report with the Oracle results, diff, Friction Log and transcript, so that I can see why it failed.
20. As a guide maintainer, I want parallel Runs isolated by table and database, so that an Iteration can run several Runs at once.
21. As a guide maintainer, I want a hidden Reference Migration that passes every Oracle check, so that the Oracle is demonstrably passable; an individual failure still needs diagnosis before attribution to the guide.
22. As a guide maintainer, I want the Oracle self-tests specified below, so that I know it accepts a correct migration and detects the important failure modes.
23. As a guide maintainer, I want the self-test to use Fake Migrators and spend no tokens, so that I can run it whenever the harness changes.
24. As a guide maintainer, I want an Iteration to run several Runs, then one Editor pass over all their results, so that edits respond to patterns, not to one Run's noise.
25. As a guide maintainer, I want the Editor to change only the guide and a Review List, so that each Iteration changes exactly one thing.
26. As a guide maintainer, I want the Editor forbidden from adding new compatibility claims, so that the guide never asserts something a test does not prove; the citation gate only proves cited names exist.
27. As a guide maintainer, I want claims with no test recorded on a Review List, so that gaps in test coverage become work items, not invented citations.
28. As a guide maintainer, I want the guide's citation test run as a hard gate after every Editor edit, and the edit reverted if it fails, so that the Loop can't break the guide's link to its tests.
29. As a guide maintainer, I want the Editor on a strong model by default, so that revisions are careful.
30. As a guide maintainer, I want the Loop to enforce the normative convergence and maximum-Iteration rules, so that recurring friction, or an Iteration that never really ran, can never count as converged.
31. As a guide maintainer, I want a Loop Summary of pass rates, new friction, kept and reverted edits and the Review List, so that I can review the result before committing.
32. As a guide maintainer, I want nothing auto-committed, so that I review every guide change before it lands.
33. As a guide maintainer, I want skill drift the Editor notices reported rather than edited, so that customer-shipped skills change only through deliberate review.
34. As a repo contributor, I want the harness unreachable from `pnpm test` and absent from CI, so that it never spends tokens or needs credentials in ordinary test runs.
35. As a guide maintainer, I want the Migrator and Editor to be swappable commands with a defined contract, so that the pipeline can be tested with fakes and other agents can be tried later.
36. As a guide maintainer, I want every Run classified by the normative outcome rules below, so that diagnosis determines whether evidence warrants guide edits and infrastructure failures neither trigger edits nor count toward convergence.
37. As a guide maintainer, I want each Run to preserve the normative Run Manifest, so that any Run can be reproduced.
38. As a guide maintainer, I want the isolation acceptance cases specified below, so that isolation is demonstrated rather than assumed.
39. As a guide maintainer, I want friction items reconciled by the normative Iteration rules, so that recurring friction stays open and missing Friction Logs cannot resolve it.
40. As a guide maintainer, I want an Iteration whose Run Slots could not all finish because of exhausted infrastructure retries marked incomplete, so that it can never count as clean.
41. As a guide maintainer, I want the restricted App Host contract specified below, so that executing migrated code cannot expose Protected Resources.
42. As a guide maintainer, I want every Run to produce a valid structured Friction Log, with an explicit empty list when there is no friction, so that a missing or malformed Friction Log fails the Run instead of reading as "no friction".

## Implementation Decisions

- Modules: Run driver (infra, workspace, seeding, Migrator invocation, Oracle, Run Report); Oracle (behaviour, no-rewrite and static layers); Reference Migration plus Fake Migrators for the self-test; Migrator adapter (headless Claude in a restricted Migrator Environment); Iteration driver with Editor adapter and citation gate; Loop driver.
- The Fixture App and its glossary already exist in the harness directory. Before invoking a Migrator, remove the README sentence pointing it at a "harness acceptance command" and replace its fixed friction.md instruction with the schema and environment-named Friction Log output path. These are harness workspace preparation steps; the repository Fixture App remains unchanged in this planning PR.
- Store provisioning: provision two Store Sets per Run, one for the Migrator and one for the Oracle. Each set has a dedicated DynamoDB Local container and a per-Run database on its respective shared Postgres container. Clone databases from an EQL v3 template, make each database owned by its per-Run role, with CREATE privileges on the application schema needed by createStores and revoke CONNECT from PUBLIC, including template and maintenance databases; roles receive no memberships granting other access. The harness alone holds admin credentials for provisioning and snapshots; application initialization and seeding use each Store Set's per-Run role, so that role owns the application tables it creates. Migrators may reach only their Migrator Stores; App Hosts may reach only their Oracle Stores, using their respective per-Run roles.
- Local endpoint topology: preserve the Fixture App's loopback-only store-host validation. Each Migrator Environment and App Host has its own loopback forwarders to its assigned store endpoints. Enforce destination and port policy outside application control; never allow all host-loopback ports or expose Docker sockets. A container implementation must provide these namespace-local forwarders rather than passing container DNS names to the Fixture App.
- Seeding: the unmigrated Fixture App initializes and writes Legacy Data and Mutation Data into both Store Sets using each set's per-Run role before the Migrator starts. Mutation Data is excluded from the no-rewrite snapshot. The Oracle snapshots its own Legacy Data immediately after seeding.
- **App Host**: the Oracle never imports or runs migrated code in the harness process.
  - Installing the migrated workspace's dependencies, including any lifecycle scripts, and calling its createApp both happen in a per-Run App Host. That is a separate OS-restricted process, with the App Host policy enforced independently of the Migrator Environment policy.
  - Its filesystem view is a copy of the migrated workspace only.
  - Its network egress permits only the npm registry, CipherStash services and this Run's Oracle Stores, with the Run's Oracle role.
  - It exposes the Fixture App README API to the harness over a narrow request/response channel (JSON over stdio), one call per message.
  - Protected Resources remain outside the App Host filesystem and credential scope.
  - Static checks read the installed workspace copy used by the App Host from the harness without executing its files. Inspect after lifecycle scripts, including scripts that introduce a removed endpoint shim. The App Host's application files are then read-only through verification; record their content hashes and refuse a pass if the files checked differ from those executed.
- Snapshot scope: no-rewrite acceptance covers independently seeded Oracle Stores and the deployed application behaviour exercised by the Oracle. Migrator Stores are disposable exploration state; the current baseline does not claim their contents remain unchanged during exploration. A migration that rewrites deployed legacy bytes still fails the Oracle checks. Any future guarantee about exploratory writes requires separate Migrator-store snapshots and acceptance cases.
- Oracle order, against Oracle Stores only, with every app call made through the App Host: (1) read-only behaviour checks on Legacy Data (get, every find*, getPostgres, findPostgres*); (2) no-rewrite comparison of every Legacy Data DynamoDB `__source`/`__hmac` and Postgres `c`/`hm` against the snapshot; (3) mutating behaviour checks on Mutation Data: put with a new pk absent from Oracle Stores, verify the fresh write and its lookups, then setActive, copyToPostgres and copyToDynamo on Mutation Data, never on Legacy Data; (4) the migration layer.
- Migration layer: checks that hold only for a migrated app, so the unmigrated app is expected to fail every one.
  - Static: `@cipherstash/protect`, `@cipherstash/protect-dynamodb` and `@cipherstash/schema` are absent from imports, the manifest and the lockfile; `@cipherstash/protect-ffi` is allowed only at the version the resolved Stack depends on (the legacy 0.18.1 must be gone); the CS_CTS_HOST/CS_ZEROKMS_HOST shim is removed.
  - Stored-shape: after the migrated setActive on a Mutation Data record, the item has no `active__hmac` (guide step 5). This is asserted on the stored item, not through findActive: a correct migration implements findActive by decrypting and filtering, which a stale HMAC does not affect.
- Oracle pass means all layers pass.
- Protected Resource policy: exclude the source checkout except explicitly exported copies, Oracle source and assertions, snapshots, Reference Migration, raw artifacts, other Runs' workspaces and credentials, and host-side model credentials from restricted processes. Assigned application credentials are available only to the process that needs them and never to the Editor. The actor-specific store permissions below additionally exclude Oracle Stores from the Migrator and all stores from the Editor.
- Isolation is enforced, not requested, with a host-side broker for the agent.
  - The agent process, which talks to the model service and holds its credentials, runs on the host, outside the Migrator Environment.
  - Every command it executes (shell, node, npm, psql) runs inside the OS-restricted Migrator Environment, whose filesystem view is limited to the workspace and whose network egress permits only the npm registry, CipherStash services (CTS, ZeroKMS) and the Run's Migrator Stores. The model service is not reachable from the Migrator Environment, and model credentials are not in its environment or filesystem.
  - The host model runtime exposes only the harness-owned isolated command tool. Disable built-in file, shell, WebFetch and WebSearch tools, arbitrary MCP servers, plugins, hooks and inherited user/project settings. Test that all application file and command operations traverse the restricted broker and that no alternative host or network tool is available; fail setup if the runtime's actual tool inventory differs from the allowlist. Issue #1534 must select and demonstrate an isolation implementation satisfying the policy and supervision contract before executing untrusted application code; #1537 reuses that verified implementation for agent commands. That choice is an implementation prerequisite, not a configurable backend interface in the first version.
  - The tool allowlist stays as a further layer. The Migrator Environment gets CS_* credentials and the Migrator Stores' URLs and role credentials, and sees only the copied guide and the Fixture App.
- Registry documentation: npm installation necessarily makes package documentation available, including tarball READMEs, and registry metadata can contain instructions. Retain broker commands and responses and supervisor file-access evidence so explicit registry documentation requests and reads of installed documentation are attributable. Record this exposure in the Run Report and flag observed supplementary-documentation use for review. A passing Oracle alone establishes application correctness, not that the copied guide was sufficient; a guide-only claim requires review of that evidence, and unknown or incomplete documentation-access evidence cannot establish guide-only success. Do not claim that network allowlisting or a command-name filter excludes all documentation.
- The Migrator is headless `claude -p`: Sonnet by default, `acceptEdits`, with configurable limits defaulting to 40 minutes and 200 turns.
- Stack source: published npm, default range `^1.2.1`, or a tarball packed from the tree. Resolved once per Loop (or per standalone Run or Iteration) to an exact version or tarball digest, which every Run installs.
- Run Manifest: every Run Report records the exact Stack version or tarball digest, guide content hash, Fixture App revision, model identifiers and agent configuration (allowlist, limits, Migrator Environment and App Host policy identifiers).
- Runtime supervision: every real Run and Editor invocation uses a host-owned supervisor outside the restricted processes. The selected implementation must deliver filesystem and network access events for all descendant processes through an authenticated, actor-tagged event stream inaccessible to the application. Events distinguish denied access from successful access, include resolved resource identity and policy decision, and are correlated with the actor's permitted resources. An implementation without this capability, or a broken event stream, fails provisioning as `infrastructure`; it must not claim breach detection from agent output. A successful forbidden access is successful access to a path or network destination outside the actor's policy, established by the supervisor's trusted event stream. On receipt, the supervisor terminates the actor and every descendant, including detached processes and children in new sessions, prevents later app/tool calls and aborts the Loop; do not promise zero latency before the event arrives. The same rule applies to Migrator, App Host and Editor. Use a per-actor container/cgroup or prevent descendants escaping the teardown boundary; killing a process group alone is insufficient. Timeout cleanup obeys the same descendant-complete rule. Put synthetic protected files and forbidden listener canaries outside permitted views for startup probes in every real invocation; canaries contain no real secrets. Exercise the same supervisor in self-tests, including a controlled policy mismatch that emits a successful forbidden-access event. No universal covert-access detection is claimed.
- Isolation observations: a denied access is recorded separately from a successful forbidden access. Filesystem/network events and Postgres CONNECT logs supply trusted evidence where applicable. Reading an environment variable produces no filesystem or network event, and an empty DynamoDB listing alone does not establish isolation: assert model credential canaries absent and other Runs' tables absent using harness-owned probes and store inspection. Do not trust a Fake Migrator's self-reported verdict. Recovered denied exploration can still yield pass or friction-only under the normal outcome rules.
- Failure classification: retain all observed failures, and select one primary outcome in the following order. Outcomes are independent of guide attribution.
  1. `isolation-violation`: the supervisor establishes a successful forbidden access (for example a protected canary was read or a forbidden connection succeeded). Apply the runtime-supervision stop rule, retain available evidence and clean up. This fails the Run, is not retried, and aborts the Loop for human investigation; it is not sent to the Editor. A denied attempt alone never produces this outcome.
  2. `infrastructure`: verified provisioning or enforcement setup failure, including inability to establish required isolation. Stop dependent stages; an application denial is not infrastructure. Pre-Migrator dependency installation, seeding, snapshot or unmigrated Fixture App initialization failures occur before any migration and are harness setup failures in this category, including ordinary setup exceptions; report their stage and cause explicitly.
  3. `agent-limit`: time/turn limit, crash or non-zero agent exit.
  4. `install`: an unrecovered dependency installation failure in the harness-controlled migrated App Host installation stage. Pre-Migrator installation failures are `infrastructure`, eligible for the infrastructure retry policy and never consumed as completed migration evidence. Failed npm commands during a Migrator session are transcript evidence, not `install` outcomes; if the Migrator recovers, subsequent checks decide the result. A finished Migrator leaving an un-installable app fails the App Host installation. An agent crash instead gives `agent-limit`.
  5. `invalid-friction-log`: missing or schema-invalid Friction Log after a finished Migrator, even if Oracle checks also fail.
  6. `behaviour`: Oracle failure after a finished Migrator.
  7. `friction-only`: Oracle passed and the valid Friction Log contains actionable friction.
  8. `pass`: Oracle passed, the Friction Log is valid and has no actionable friction.
- Run stages are provisioning, unmigrated dependency installation, seeding/snapshot, Migrator, Friction Log validation, App Host installation and Oracle checks, then Run Report. A failed prerequisite skips dependent stages and records them as skipped. Independent diagnostics may continue except after a successful forbidden access. A finished Migrator with an invalid Friction Log may still receive Oracle diagnostics. Primary outcome is selected from unresolved stage failures and successful forbidden accesses by the precedence above, never by the last stage to fail.
- Editor eligibility: a Run contributes candidate guide evidence only if the Migrator was invoked and produced an exported Run Report, has no successful forbidden access and has a non-infrastructure outcome. Pre-Migrator install/setup failures cannot reach the Editor. If no Run is eligible, skip the Editor and record why; the Iteration is not clean. Infrastructure Runs are excluded from Editor input and retried up to a configurable limit. An Iteration is complete only when every Run Slot ends in a non-infrastructure outcome. Exhausted retries make it incomplete: no Editor pass, no clean result, a broken clean streak, and one Iteration consumed toward the maximum. Secondary failures remain visible regardless of primary outcome.
- Guide section identity: parse Markdown ATX headings using lowercase ASCII slugs (non-alphanumeric runs become hyphens), with duplicate slugs suffixed by occurrence number; text before the first heading is `preamble`. Record IDs and line ranges against the input guide hash. A renamed or moved section is handled as a deletion and insertion; no persistent section aliases are maintained.
- Evidence identity: the harness assigns immutable IDs to redacted evidence records as `run-id/kind/ordinal`; records contain the producing stage, kind, stable check or tool-call ID, payload digest, attribution-usable flag and guide revision. Kinds include `oracle-check`, `friction-item`, `agent-tool`, `stage-error` and `log-validation`. The Editor cannot mint or alter the evidence catalog. Every export carries the same IDs across inline summaries and opened artifacts.
- Attribution gate: the Editor returns a schema-validated Review List with `needs-test`, `skill-drift`, `diagnosis` and `edit-mapping` entries. Diagnoses contain ID, eligible Run IDs, existing evidence IDs, original guide section ID, attribution (`guide-gap`, `migrator-error`, `harness-defect`, `unknown`) and rationale. A `guide-gap` requires at least one attribution-usable evidence record other than `log-validation` and an eligible Run; an invalid Friction Log alone is mechanically insufficient.
- Edit mapping: the harness parses headings in the input guide into section IDs and maps changed lines using a deterministic unified diff with zero context. Each changed hunk is identified by its ordinal plus before/after guide hashes. An edit-mapping entry names that hunk, one or more guide-gap diagnosis IDs and all touched original section IDs. Insertions use the preceding original section (document start is `preamble`); deletion and heading changes use the original sections covering removed lines. Moves, heading renames and restructures require mappings for both the deletion and insertion hunks under the same rules. Reject missing evidence, unaccounted hunks or any touched original section without a covering diagnosis. This checks provenance and coverage, not semantic truth; human review still assesses attribution and claims.
- Command contract for swappable Migrator and Editor commands: input is the working directory plus environment variables naming the guide, workspace, store URLs (Migrator) or Iteration Results directory (Editor), and the output paths; output is files at those paths (Friction Log for the Migrator; edited guide and Review List for the Editor); exit 0 means finished, non-zero means the agent itself failed; the harness enforces the time limit by terminating the actor and all descendants under the runtime-supervision contract and records `agent-limit`.
- The Friction Log is a schema-validated list with an explicit empty list for no friction. Each entry contains the input guide section ID, a short issue slug, an actionable/informational flag, what was unclear/wrong/missing and what the Migrator did instead. The issue slug is lowercase ASCII words joined by hyphens describing the issue. The friction identifier is the pair of input guide section ID and short issue slug. Every Migrator starts without prior Friction Logs, friction identifiers, diagnoses or workarounds in its prompt or workspace; the harness reconciles identifiers after collecting the independent Runs. Matching pairs identify recurring friction; different pairs remain separate. Heading changes or different issue wording can produce new identifiers, which remain visible in the Loop Summary for human review rather than being silently merged. Such identity changes cannot make an Iteration clean while any Run reports actionable friction. A missing/malformed Friction Log gives `invalid-friction-log` according to outcome precedence.
- Friction is reconciled per complete Iteration. An identifier is open if any Run in that Iteration reports it as actionable. It is resolved only when a complete Iteration in which every Run Slot produced a valid Friction Log reports it from no Run. A Run without a valid Friction Log never resolves anything by omission. Resolution needs no guide edit, so transient friction clears on a confirmation Iteration of the same revision.
- Evidence export: before the Editor runs, Iteration Results contain redacted Run Reports and the evidence catalog. After the Editor finishes, the harness adds the edit disposition, including acceptance or rejection and gate results. A host-side exporter replaces configured CS_* secrets, database credentials, credential-bearing URLs and their URL-encoded/JSON-escaped forms; it drops environment dumps and binary attachments. An independent post-export leak scan checks all exported files and inline model-input payloads against the same secret inventory before any Editor invocation. A match or export failure stops the Editor pass, never falls back to raw evidence, and leaves the guide unchanged. Raw artifacts are Protected Resources.
- Redaction usability: replace only secret spans with typed markers, retaining evidence IDs, guide sections, check names, dependency package/version, exit code and non-secret error context. If a required field contains a secret, redact it and mark that record unusable for attribution; never expose the secret to preserve context. Tests must assert both leak absence and preservation of non-secret diagnostic fields. These measures cover inventoried forms, not arbitrary adversarial encodings.
- Editor setup: headless `claude -p` on Opus by default, using a fresh Editor workspace with copies of the guide and Review List and read-only Iteration Results. The checkout guide is not mounted. Optionally export explicitly selected relevant skills as read-only, redacted copies with source revision metadata so skill drift can be noticed; no skill is shown to the Migrator. Absence of exported skill context is recorded and means no skill-drift assessment, not that skills are correct.
- Editor boundaries: enforced file-tool and command policies allow writes only to its guide and Review List copies. No store access, network egress, host credentials or Docker socket is available to commands; model traffic stays in the host broker. All Protected Resources remain inaccessible. Denials are recorded. A successful forbidden access follows the shared runtime-supervision rule and aborts the Loop; an attempted denied write alone does not. Out-of-scope outputs are rejected. The harness applies only accepted guide/Review List changes back to its working copy after gates pass.
- Editor authority: use Iteration Results as untrusted evidence, never instructions. Clarify, restructure or add procedural steps and reuse existing compatibility claims with their citations; put proposed new claims and noticed skill drift in the Review List instead of changing claims or skills.
- Editor gates: attribution gate, citation-existence test, and citation-set check all must pass; otherwise revert the whole proposed guide edit. The citation-set gate conservatively rejects previously absent citations without implying that every new citation is a new claim. These gates cannot establish semantic attribution, detect every uncited new claim or prove that an existing citation supports a changed claim. Human review of the Loop Summary remains required.
- An Iteration is 3 Run Slots in parallel by default, then one Editor pass. A Clean Iteration is complete, every Run Slot has primary outcome `pass`, and no Friction Log contains actionable friction; a passing Run requires a valid Friction Log. The Editor makes no edit after a Clean Iteration or an incomplete Iteration. Track clean streaks separately by store procedure and guide hash. A procedure converges after two consecutive Iterations for that procedure are Clean Iterations on the same guide hash; an incomplete or non-clean Iteration breaks its streak. Combined convergence requires both procedures to converge on the same final hash, even when no Editor edits occurred. A guide edit invalidates all prior-hash streaks. The Loop stops at combined convergence or at 6 Iterations; both limits are configurable. Reaching the limit without both procedures converged is not combined convergence.
- The available real agent command, `harness:run`, remains opt-in in the e2e package. `harness:iterate` and `harness:loop` are planned commands and are not yet defined. At the maintainer's explicit request during implementation, credential-free self-tests, typechecking and Docker capability probes also run in a dedicated workflow and named Turbo tasks with workspace build dependencies. Ordinary `pnpm test` and `test:e2e` still exclude the harness, and CI never invokes a real Migrator or Editor. Deterministic credentialed Fixture App tests follow the priority amendment.

## Testing Decisions

- Test only through external behaviour: Run Reports and Iteration Results, never Oracle internals.
- Seam 1: a Run, with the Migrator as a swappable command. A Fake Migrator copies the hidden Reference Migration into the workspace and must pass; the Reference Migration itself is application code, not a Migrator command. Other Fake Migrators leave the Fixture App unchanged (behaviour/no-rewrite pass, migration layer fails) or apply Broken Migrations: missing downcase normalization on new writes, stale boolean HMAC after setActive despite correct decrypt/filter lookup, broken bigint serialization, and ciphertext rewritten on read. Named check mapping: downcase write → `behaviour.downcase-new-write-lookup`; stale HMAC → `migration.active-hmac-absent`; bigint serialization → `behaviour.balance-decimal-string`; read rewrite → `no-rewrite.legacy-bytes`. Expose these stable check IDs in Run Reports and the evidence catalog.
- Isolation acceptance cases exercise the Protected Resource policy above, for both Migrator and App Host filesystem probes. Trusted harness assertions validate probe results; the supervisor must collect the required filesystem and network access events. Cases include filesystem denial, forbidden-host/model-service connections, a Migrator denied access to its own Run's Oracle Stores and every other Run's Store Sets, other-Run Postgres CONNECT denial with server-side log evidence, and own DynamoDB endpoint containing no other Run's tables. Separate canary checks establish that model credentials are absent from command environments and mounted files; reading an absent variable is not an access violation.
- Local topology tests, in both Migrator Environments and App Hosts, permit assigned loopback forwarders but deny a listener on an unrelated host-loopback port, other Runs' forwarded ports, and Docker socket access. Run the unchanged Fixture App through assigned endpoints to prove its loopback validation is satisfied.
- App Host cases execute Broken Migrations whose createApp or dependency lifecycle script probes Protected Resources or forbidden hosts. The supervisor independently records denied filesystem and network access, and the harness confirms no protected content or connection was obtained. A caught denial alone does not fail otherwise valid application behaviour; an uncaught exception may fail installation or behaviour. A controlled policy mismatch, using the same active supervisor and canary resources as real Runs, must detect a successful protected canary read, produce `isolation-violation`, stop further calls and abort the Loop.
- Additional acceptance cases cover an App Host lifecycle script introducing the endpoint shim into the installed copy, a detached descendant surviving a process-group kill, explicit registry README retrieval and installed README reads, and a no-edit Loop where only one store procedure converges. These must respectively fail migration checks, prove complete teardown, record supplementary-documentation use, and refuse combined convergence.
- Editor isolation cases cover every Protected Resource, including other workspaces, and denied writes outside the guide and Review List. Also deny store, arbitrary-host and model-service egress from Editor commands. Verify no out-of-scope file changes survive; rejected Editor output preserves the prior guide.
- Redaction tests place unique credential canaries into transcript, diff, Friction Log, error text and manifest inputs, including URL-encoded and JSON-escaped variants. Assert exported Iteration Results and model-input payloads contain none of those canaries, and that raw artifacts cannot be opened by the Editor. Export failure or a secret found by the post-export leak scan must prevent an Editor invocation. Verify package/version, exit codes, section IDs and non-secret error context survive redaction, and secret-bearing required fields are marked unusable.
- Outcome precedence tests cover every category and every adjacent pair that can coexist, using controlled failures visible at the Run seam; mutually exclusive or skipped categories are checked for correct exclusion instead. Include a Migrator crash after a failed npm tool command (`agent-limit`, no `install` stage failure), a recovered npm command followed by successful Oracle checks (pass or friction-only), App Host install failure plus invalid Friction Log, absent Friction Log plus Oracle failure, pre-seeding install failure with dependent stages skipped, ordinary denied exploration followed by a valid migration (no isolation-violation), seeding and snapshot exceptions (`infrastructure`, no Editor), pre-Migrator install failure (no Editor), and a successful forbidden-access event followed by an attempted later call (later call never runs). No Fake Migrator install-report channel is required: install failures are injected through the harness-controlled install stages.
- Attribution gate tests supply Editor outputs with missing diagnosis fields, invented evidence IDs, log-validation-only evidence, unknown/mismatched section or hunk IDs, heading rename/move without complete deletion and insertion mappings, a diff hunk without a diagnosis, and `migrator-error`, `harness-defect` or `unknown` attribution for a changed hunk: each must preserve the prior guide. A structurally valid guide-gap diagnosis linked to exported evidence permits a correction, including a mapped multi-section restructure. An exported skill copy permits a skill-drift item but cannot be edited. No test claims to prove the truth of its rationale.
- Friction Log validation: a Fake Migrator that exits 0 with no Friction Log, and one that writes a malformed one, must give the `invalid-friction-log` outcome even when the migration itself is correct (a Fake Migrator copying the Reference Migration but writing no Friction Log).
- Seam 2: an Iteration, with the Editor as a swappable command. A Fake Editor that adds a fabricated citation must be reverted; a clean edit must be kept. Infrastructure-classified Runs must be excluded from Editor input. Stop-condition tests use canned Iteration Results, including recurring friction (never clean), two Clean Iterations on different guide revisions (not converged), an Iteration with exhausted infrastructure retries (incomplete, breaks the streak), all Runs infrastructure-failed (incomplete, not clean), friction reported by one of three Runs (still open), transient friction absent from a full confirmation Iteration on the same revision (resolved), and open friction omitted by a Run with no valid Friction Log (still open, and the Iteration is not clean).
- A Fake Editor that adds a real but previously uncited test citation must be reverted by the citation-set check. Uncited new claims and new claims attached to existing citations are left to human review of the guide diff; no test claims to catch them.
- Tests that need credentials and Docker are gated like the compat suite.
- Prior art: the credential-gated compat and crossover vitest suites in the e2e package, and the guide citation test (protect-upgrade-guide) used as the Editor gate.

## Out of Scope

- Running real Migrators, Editors or Loops in CI. Dedicated credential-free
  self-tests and capability probes are permitted, as are the deterministic
  credentialed tests specified in the priority amendment.
- The baseline Fixture App's Postgres is already EQL v3. Upgrading a v2 Postgres database is covered by the priority amendment and its separate extension, not by this baseline.
- JSON (`dataType('json')`) columns, date columns, lock contexts, nested attributes, and index kinds beyond equality.
- Real AWS DynamoDB; DynamoDB Local only.
- The Editor editing skills, the Fixture App, the Oracle or the compat tests.
- Auto-committing guide changes or opening PRs.
- Upgrade guides beyond the two v2-to-v3 store procedures in the priority amendment.

## Further Notes

Tickets: #1534, #1535, #1536, #1537, #1538, #1539.

## Contract changes from the issue snapshot

This ADR is the source of truth; #1540 tracks the epic. The `report` outcome is named `invalid-friction-log`, and the broader Review List replaces the needs-test list. The Reference Migration establishes passability rather than guide attribution. Clean means no actionable friction. Explicit supervision, Editor restrictions, evidence redaction, attribution provenance, Mutation Data and local topology make the original isolation and guide-edit requirements concrete. The command seam supports both deterministic fakes and alternate agent implementations. Denied attempts are recorded but do not themselves fail a Run; this deliberately replaces the issue snapshot's denial-implies-failure rule, reserving `isolation-violation` for a successful forbidden access. Friction identifiers use the original guide-section-plus-issue-slug pair; the proposed harness-assigned catalog IDs, prior-friction prompt input and section aliases are removed so earlier workarounds cannot mask guide gaps.
