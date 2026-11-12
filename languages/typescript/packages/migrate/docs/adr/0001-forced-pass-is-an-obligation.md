---
status: accepted
date: 2026-10-16
---

# A forced pass is an obligation on the column migration, enforced by migrate

## Decision

Whether the target column must be overwritten is a fact about the target
column's contents, not about one run. It is therefore held once, on the column
migration, as an obligation derived from the column migration's events. An
obligation opens when a forced pass starts (in either direction) or when a
reverse column migration begins on a twin that already holds values. It closes
only when a forced pass completes, or, for the up-front reverse case, when the
operator records a waiver asserting the existing values are current. A waiver
cannot close the obligation of a forced pass that has already started, because
by then the target column is partly overwritten. While an obligation is open,
every run is a forced pass, whatever the caller passes. `@cipherstash/migrate`
enforces this rule itself, not the `stash` CLI, because customers embed
`runBackfill` and `runDecryptBackfill` in their own workers and would otherwise
bypass it.

#1193 first enforced an open obligation in the reverse direction, in
`runDecryptBackfill`. #1276 (the first part of #1217) moved the decision into
`ColumnMigration` for both directions. `runBackfill` and `runDecryptBackfill`
plan every run through it, so in both directions it forces a run while an
obligation is open, forces a reverse run that starts on a twin that already
holds values with no waiver recorded, and refuses to start a column migration
while another is open on the same pair. `ColumnMigration.confirmDualWrites`
records the waiver, and refuses it once a forced pass has started. The `stash`
CLI adds the flags (`--force`, `--confirm-plaintext-current`) and its own
messages on top of these rules.

## Considered options

- **`force` as a per-run option, checked when resuming** (what was first built
  for reverse). An interrupted forced pass that failed before its first
  checkpoint left no cursor, so the next plain run started a fresh, unforced
  pass. That kept stale values in the twin, and the drop then removed the only
  current copy.
- **Refuse unforced runs while a forced pass is incomplete.** This is safe, but
  every caller has to remember the flag, and that is how the per-run model came
  about.
- **Enforce the rule in the CLI only.** Embedded workers would skip it.

## Consequences

- At most one column migration is open per column pair. A reverse column
  migration cannot start until the forward drop migration is generated, the
  source column is recorded as removed, or the forward migration is aborted.
  A generated drop may not yet be applied. Aborting a forward column migration
  is a separate operation, and `@cipherstash/migrate` does not provide it yet.
- Every backfill event in `cs_migrations` (started, checkpoint, completed and
  error) records the pass mode as `details.force`, in both directions. The
  dual-write confirmation and drop events do not. The obligation has no events
  of its own: `ColumnMigration` derives it from the event trail. A dual-write
  confirmation with `details.existingTwinValues` and no `details.waiver` opens
  the up-front obligation, and a later confirmation with `details.waiver`
  closes it. A forced pass's running events open the forced-pass obligation,
  and its completion closes it. Events written before #1276 differ, and
  `ColumnMigration` still reads them: they record `force: true` on a forced
  pass only, on `backfill_started` alone in the forward direction and on every
  event in the reverse direction, and they record the up-front choice as
  `details.acknowledgedWith`. The shape of `details` is effectively public, so
  changes to it go in a changeset.
