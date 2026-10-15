# Migrate

Moves an existing column of a customer's database between plaintext and encrypted form without downtime, tracking every step so an interrupted move can resume. Used by the `stash encrypt *` and `stash decrypt *` commands and by customers who embed it in their own workers.

## Language

### The move

**Column migration**:
One direction applied to one column, from the first dual-write confirmation to the drop of the old column.
_Avoid_: lifecycle, rollout, reverse lifecycle

**Direction**:
Which way a column migration moves data: **forward** (plaintext to encrypted) or **reverse** (encrypted to plaintext).
_Avoid_: mode, encrypt/decrypt flow

**Source column**:
The column a column migration reads from and eventually drops.

**Target column**:
The column a column migration fills and keeps.

**Twin**:
The other column of the pair, in either direction. In forward it is the encrypted column; in reverse it is the plaintext column.
_Avoid_: plaintext twin, shadow column

**Phase**:
The recorded stage a column migration is in, such as dual-writing, backfilling, cut over, or dropped.
_Avoid_: state, status

**Dual-writing**:
The phase in which the application writes every change to both the source and target columns.

**Abort**:
Abandoning a column migration that has not been dropped, leaving the source column as the column of record. Distinct from a reverse column migration, which starts only after a forward one is dropped.
_Avoid_: rollback, revert

**Rollout**:
The work before dual-writing is confirmed: adding the target column and deploying dual-write code. Not a name for the whole column migration.

### Filling the target

**Backfill pass**:
One logical sweep that fills the target column from the source column. It may span several runs through resumes.
_Avoid_: backfill (alone, when the pass is meant), job

**Run**:
One invocation of a backfill, from the CLI or a worker. A run either starts a backfill pass or resumes one.
_Avoid_: pass (when one invocation is meant)

**Forced pass**:
A backfill pass that overwrites values already in the target column instead of skipping them.

**Obligation**:
A condition recorded on a column migration that must be met before a later phase can be entered. An open obligation to complete a forced pass arises when a forced pass starts, or when a reverse column migration begins on a twin that already holds values; while it is open, every run is a forced pass.
_Avoid_: acknowledgement, hazard flag

**Waiver**:
An operator's recorded assertion that a twin's existing values are already current, which closes the up-front obligation of a reverse column migration without a forced pass. It cannot close the obligation of a forced pass that has started.
_Avoid_: confirmation, acknowledgement
