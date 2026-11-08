# Migration Harness

A Loop that tests an upgrade guide by having agents follow it. A Migrator upgrades a Protect.js application using only the guide, an Oracle judges the result, and an Editor revises the guide from what went wrong.

## Language

**Fixture App**:
The small Protect.js application, storing encrypted data in DynamoDB and Postgres, that every Run starts from.
_Avoid_: sample app, demo app, test app

**Run**:
One configured execution of the harness pipeline on a fresh Fixture App, ending in a Run Report; setup or agent failures may prevent the Migrator or Oracle from running.
_Avoid_: trial, attempt, episode

**Legacy Data**:
Records the unmigrated Fixture App writes before a Migrator starts, distinct from Mutation Data. The Oracle copy is expected to remain unchanged, and a no-rewrite failure detects any change; the Migrator copy may be changed during exploration.
_Avoid_: seed data, fixtures, old data

**Iteration**:
One or more Runs against a single revision of the guide, followed by at most one Editor revision.
_Avoid_: round, cycle

**Migrator**:
The agent that performs the upgrade, seeing only the guide and the Fixture App copy.
_Avoid_: subject, worker, executor

**Oracle**:
The deterministic checks that decide whether a Run passed. No agent takes part, and the Migrator never sees them.
_Avoid_: grader, judge, evaluator

**App Host**:
The restricted process in which the Oracle installs and runs a migrated Fixture App, with access to the npm registry, CipherStash services and only its own Run's Oracle Stores, while Protected Resources remain outside it.
_Avoid_: runner, worker, sandbox

**Editor**:
The agent that revises the guide from eligible Run Reports in Iteration Results.
_Avoid_: improver, reviewer, author

**Reference Migration**:
A hand-written, correct upgrade of the Fixture App that proves the Oracle can be passed. Neither the Migrator nor the Editor ever sees it.
_Avoid_: golden app, solution, answer key

**Friction Log**:
The Migrator's own record of where the guide was unclear, wrong or silent.
_Avoid_: notes, feedback, report

**Mutation Data**:
Records written by the unmigrated Fixture App for mutating Oracle checks, separate from Legacy Data.
_Avoid_: reserved records

**Run Slot**:
One configured position in an Iteration, filled by a Run and any infrastructure retries until it has a non-infrastructure outcome or exhausts retries.
_Avoid_: run position

**Loop**:
A bounded sequence of Iterations that evaluates and revises one guide toward consistent passing Runs without actionable friction.
_Avoid_: iteration loop

**Fake Migrator**:
A deterministic substitute for a Migrator command, used to exercise Run outcomes without model tokens.
_Avoid_: mock migrator

**Review List**:
The typed review artifact containing claims that need tests, skill drift, and evidence-linked diagnoses supporting or rejecting guide edits.
_Avoid_: Needs-test List

**Run Report**:
The harness-produced record of a Run's outcomes, Oracle results, Run Manifest, diff, Friction Log and transcript.
_Avoid_: run output

**Fake Editor**:
A deterministic substitute for an Editor command that exercises Iteration acceptance without model tokens.
_Avoid_: mock editor

**Broken Migration**:
A deliberately incorrect migrated Fixture App used to establish a specific Oracle failure or isolation result.
_Avoid_: fake migration

**Protected Resources**:
The source checkout (not explicitly exported copies), Oracle source and assertions, snapshots, Reference Migration, raw artifacts, other Runs' workspaces and credentials, and host-side model credentials excluded from restricted processes. Assigned application credentials are not protected from the process that needs them, but never belong in Editor evidence.
_Avoid_: hidden Oracle evidence, hidden set

**Iteration Results**:
The exported, redacted Run Reports and evidence catalog for one Iteration, extended with edit disposition after the Editor finishes.
_Avoid_: iteration output

**Loop Summary**:
The human-review artifact aggregating Iteration Results, pass rates, friction, kept/reverted edits and the Review List across a Loop.
_Avoid_: loop report

**Clean Iteration**:
A complete Iteration in which every Run Slot passes and no Friction Log contains actionable friction.
_Avoid_: clean round

**Store Set**:
One Run's dedicated DynamoDB Local instance and Postgres database, assigned either to its Migrator or its App Host.
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
The OS-restricted execution environment for a Migrator's commands, separate from its host-side model broker.
_Avoid_: Migrator sandbox
