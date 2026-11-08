---
status: proposed
date: 2026-11-09
---

# Test upgrade guide usability with isolated agent Runs

Compatibility tests establish supported encryption operations but cannot show
whether a reader can follow the Protect.js upgrade guide. We will use a local
Migration Harness: a Migrator upgrades a fresh Fixture App, a deterministic Oracle
checks it through a restricted App Host, and an Editor revises the guide from
Iteration Results. The [implementation plan](../../../../docs/plans/2026-11-09-migration-harness.md)
retains the reviewed requirements from [issue #1540](https://github.com/cipherstash/stack/issues/1540);
terms follow the [context glossary](../../CONTEXT.md).

## Decision

Keep agent execution separate from the process holding assertions and snapshots.
Migrators and App Hosts receive separate per-Run stores and enforced filesystem
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
- CI execution is out of scope: ordinary tests must not need model budget,
  live credentials or this harness's Docker environment.

## Consequences

Isolation and separate stores cost setup time and require observable enforcement.
Per-process loopback forwarding preserves the Fixture App's loopback-only endpoint rule.
Convergence provides evidence for this Fixture App and guide revision only.
Citation gates validate reference names, not claims; human review of guide changes
remains required. The detailed contracts and acceptance cases belong in the
implementation plan, while this ADR records the architectural choice and trade-offs.
