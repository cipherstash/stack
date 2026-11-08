# Migration Harness

A Loop that tests an upgrade guide by having agents follow it. A Migrator upgrades a Protect.js application using only the guide, an Oracle judges the result, and an Editor revises the guide from what went wrong.

## Language

**Fixture App**:
The small Protect.js application, storing encrypted data in DynamoDB and Postgres, that every Run starts from.
_Avoid_: sample app, demo app, test app

**Run**:
One Migrator's attempt to upgrade a fresh copy of the Fixture App, followed by the Oracle's verdict on it.
_Avoid_: trial, attempt, episode

**Legacy Data**:
Records the unmigrated Fixture App writes before a Migrator starts, distinct from Mutation Data. The Oracle copy remains immutable for no-rewrite checks; the Migrator copy may be changed during exploration.
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
The restricted process in which the Oracle installs and runs a migrated Fixture App, with access to the npm registry, CipherStash services and only its own Run's Oracle stores, while Protected Resources remain outside it.
_Avoid_: runner, worker, sandbox

**Editor**:
The agent that revises the guide from an Iteration's exported Oracle results, Friction Logs, diffs and transcripts.
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
The harness-produced record of a Run's outcomes, Oracle results, manifest, diff, Friction Log and transcript.
_Avoid_: run output

**Fake Editor**:
A deterministic substitute for an Editor command that exercises Iteration acceptance without model tokens.
_Avoid_: mock editor

**Broken Migration**:
A deliberately incorrect migrated Fixture App used to establish a specific Oracle failure or isolation result.
_Avoid_: fake migration

**Protected Resources**:
The checkout, Oracle source and assertions, snapshots, Reference Migration, other Runs' workspaces and credentials, and host-side model credentials excluded from agent and App Host access. Assigned application credentials are not protected from the process that needs them, but never belong in Editor evidence.
_Avoid_: hidden Oracle evidence, hidden set

**Iteration Results**:
The exported, redacted Run evidence and edit disposition for one Iteration.
_Avoid_: iteration output

**Loop Summary**:
The human-review artifact aggregating Iteration Results, pass rates, friction, kept/reverted edits and the Review List across a Loop.
_Avoid_: loop report
