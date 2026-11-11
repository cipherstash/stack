# Migration Harness

A harness that tests an upgrade guide by having agents follow it. A Migrator upgrades a Protect.js application using only the guide, an Oracle judges the result, and an Editor revises the guide from what went wrong.

## Language

**Fixture App**:
The small Protect.js application with encrypted data in DynamoDB and Postgres that is the starting point for a Run.
_Avoid_: sample app, demo app, test app

**Run**:
One execution of the harness pipeline for a Fixture App, described by a Run Report even when execution ends before migration or verification.
_Avoid_: trial, attempt, episode

**Legacy Data**:
Records from the unmigrated Fixture App used as the baseline for compatibility and no-rewrite checks, distinct from Mutation Data.
_Avoid_: seed data, fixtures, old data

**Iteration**:
One or more Runs against a single revision of the guide, followed by at most one Editor revision.
_Avoid_: round, cycle

**Migrator**:
The agent responsible for upgrading the Fixture App using the guide, without access to the Oracle or Reference Migration.
_Avoid_: subject, worker, executor

**Oracle**:
The deterministic, agent-free checks of the migrated Fixture App's behaviour, stored data and migration completeness, hidden from the Migrator.
_Avoid_: grader, judge, evaluator

**App Host**:
The execution environment for the migrated Fixture App during Oracle verification.
_Avoid_: runner, worker, sandbox

**Editor**:
The agent that revises the guide from eligible Run Reports in Iteration Results.
_Avoid_: improver, reviewer, author

**Reference Migration**:
A known-correct upgrade of the Fixture App used to establish that the Oracle can be passed, hidden from both Migrator and Editor.
_Avoid_: golden app, solution, answer key

**Friction Log**:
The Migrator's own record of where the guide was unclear, wrong or silent.
_Avoid_: notes, feedback, report

**Mutation Data**:
Records reserved for mutating Oracle checks, separate from Legacy Data.
_Avoid_: reserved records

**Run Slot**:
One configured position in an Iteration, associated with a Run and its infrastructure retries.
_Avoid_: run position

**Loop**:
A bounded sequence of Iterations that evaluates and revises one guide toward consistent passing Runs without actionable friction.
_Avoid_: iteration loop

**Fake Migrator**:
A deterministic substitute for a Migrator in harness self-tests.
_Avoid_: mock migrator

**Review List**:
The review artifact containing claims that need tests, skill drift, and evidence-linked diagnoses supporting or rejecting guide edits.
_Avoid_: Needs-test List

**Run Report**:
The harness-produced record of a Run's outcomes, Oracle results, Run Manifest, diff, Friction Log and transcript.
_Avoid_: run output

**Fake Editor**:
A deterministic substitute for an Editor in harness self-tests.
_Avoid_: mock editor

**Broken Migration**:
A deliberately incorrect migrated Fixture App used to establish a specific Oracle failure or isolation result.
_Avoid_: fake migration

**Protected Resources**:
The material reserved for the harness to preserve independent verification and isolation between Runs.
_Avoid_: hidden Oracle evidence, hidden set

**Iteration Results**:
The collected Run Reports, evidence and available edit disposition for one Iteration.
_Avoid_: iteration output

**Loop Summary**:
The human-review artifact aggregating Iteration Results, pass rates, friction, kept/reverted edits and the Review List across a Loop.
_Avoid_: loop report

**Clean Iteration**:
A complete Iteration with passing Runs and no actionable friction.
_Avoid_: clean round

**Store Set**:
The paired DynamoDB and Postgres stores assigned to one role in a Run.
_Avoid_: database pair

**Migrator Stores**:
The Store Set assigned to a Migrator for exploration and application verification.
_Avoid_: agent databases

**Oracle Stores**:
The separate Store Set accessed by the harness and App Host for deterministic Oracle checks.
_Avoid_: acceptance databases

**Run Manifest**:
The reproducibility metadata attached to a Run Report, identifying Stack, guide, Fixture App and agent configuration.
_Avoid_: run metadata

**Migrator Environment**:
The execution environment for a Migrator's commands.
_Avoid_: Migrator sandbox

**Isolation Actor**:
The policy identity attached to a restricted process and its descendants: Migrator or App Host. This differs from a database role, which grants access to a Store Set.
_Avoid_: worker, actor without its isolation context

**Runtime Supervisor**:
The trusted process outside an Isolation Actor that observes filesystem and network access, terminates it after a successful forbidden access and blocks later calls.
_Avoid_: application monitor

**Isolation Capability Probe**:
A harness-controlled check that demonstrates an enforced boundary and its trusted event stream before application execution.
_Avoid_: application-reported isolation check

**Trusted Access Event**:
A Runtime Supervisor record identifying the Isolation Actor, resource, policy decision and observed access result. Denied access differs from successful forbidden access.
_Avoid_: agent-reported verdict

**Evidence Record**:
A harness-assigned record with an immutable Run-scoped ID, producing stage, stable check or tool-call ID, payload digest, guide revision and attribution eligibility.
_Avoid_: unstructured evidence blob
