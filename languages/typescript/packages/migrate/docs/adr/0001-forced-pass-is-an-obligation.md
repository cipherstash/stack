---
status: proposed
---

# A forced pass is an obligation on the column migration, enforced by migrate

This ADR records the decided design, which is not yet fully implemented. #1193 enforces the obligation for the reverse direction (`runDecryptBackfill`). The forward direction (`runBackfill`), the waiver, and the obligation events arrive with #1217. Until then, `runBackfill` takes `force` from each run.

Whether the target column must be overwritten is a fact about the target column's contents, not about one run. It is therefore recorded once, on the column migration, as an obligation. An obligation opens when a forced pass starts (in either direction) or when a reverse column migration begins on a twin that already holds values. It closes only when a forced pass completes, or, for the up-front reverse case, when the operator records a waiver asserting the existing values are current. A waiver cannot close the obligation of a forced pass that has already started, because by then the target column is part overwritten. While an obligation is open, every run is a forced pass, whatever the caller passes. `@cipherstash/migrate` enforces this rule itself, not the `stash` CLI, because customers embed `runBackfill` and `runDecryptBackfill` in their own workers and would otherwise bypass it.

## Considered Options

- **`force` as a per-run option, checked when resuming** (what was first built for reverse). An interrupted forced pass that failed before its first checkpoint left no cursor, so the next plain run started a fresh, unforced pass. That kept stale values in the twin, and the drop then removed the only current copy.
- **Refuse unforced runs while a forced pass is incomplete.** This is safe, but every caller has to remember the flag, and that is how the per-run model came about.
- **Enforce the rule in the CLI only.** Embedded workers would skip it.

## Consequences

- At most one column migration is open per column pair. A reverse column migration cannot start until the forward one is dropped. Abandoning a forward column migration that is still in progress is a separate operation.
- Events in `cs_migrations` will carry the pass mode, and the obligation's opening and closing will be recorded as events (#1217). Today only `backfill_started` records `details.force`. The shape of `details` is effectively public, so changes to it go in a changeset.
