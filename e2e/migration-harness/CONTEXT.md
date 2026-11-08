# Migration Harness

A loop that tests an upgrade guide by having agents follow it. A Migrator upgrades a Protect.js application using only the guide, an Oracle judges the result, and an Editor revises the guide from what went wrong.

## Language

**Fixture App**:
The small Protect.js application, storing encrypted data in DynamoDB and Postgres, that every Run starts from.
_Avoid_: sample app, demo app, test app

**Run**:
One Migrator's attempt to upgrade a fresh copy of the Fixture App, followed by the Oracle's verdict on it.
_Avoid_: trial, attempt, episode

**Legacy Data**:
The immutable records the unmigrated Fixture App writes at the start of a Run, before the Migrator starts; separate Mutation Data is reserved for updates. The Oracle reads them after the upgrade and checks their ciphertext was never rewritten.
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
The restricted process in which the Oracle installs and runs a migrated Fixture App, with access to the npm registry, CipherStash services and only its own Run's Oracle stores, while hidden Oracle evidence remains outside it.
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
Records written by the pristine Fixture App for mutating Oracle checks, separate from the immutable Legacy Data snapshots.

**Run slot**:
One configured position in an Iteration, filled by a Run and any infrastructure retries until it has a terminal outcome or exhausts retries.

**Loop**:
A bounded sequence of Iterations that evaluates and revises one guide toward consistent passing Runs without actionable friction.

**Fake Migrator**:
A deterministic substitute for a Migrator command, used to exercise Run outcomes without model tokens.

**Needs-test List**:
The review artifact containing proposed claims that need evidence, skill drift, and failure diagnoses and their attribution before guide edits.

**Run report**:
The harness-produced record of a Run's outcomes, Oracle results, manifest, diff, Friction Log and transcript.
