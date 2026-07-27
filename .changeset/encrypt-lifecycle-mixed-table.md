---
'stash': patch
---

`stash encrypt cutover` and `stash encrypt drop` no longer act on — or report
success for — an encrypted column they only guessed at.

On a table holding both a legacy EQL v2 pair (`ssn` / `ssn_encrypted`) and one
unrelated EQL v3 column, the v2 ciphertext column is not classified as an EQL
column at all, so column resolution fell through to the "this is the table's
only EQL column" rule and claimed the unrelated v3 column. Three consequences,
all now fixed:

- **`cutover` reported success for work it never did.** Its EQL v3 branch had no
  guard on how the column was resolved, and returned without setting an exit
  code — so it printed "point your application at `email_enc`" and exited 0
  while the v2 rename never ran. A scripted rollout read that as complete. It
  now refuses, and exits 1, exactly as `drop` already did.

- **The recorded pairing was discarded.** `encrypt backfill` writes the true
  `encryptedColumn` to `.cipherstash/migrations.json`, so the answer was already
  on disk — but a hint that failed to resolve was dropped entirely and the
  re-resolution reached the guess. A hint naming a column that still exists but
  is not an EQL v3 column is now reported as what it is (most often a legacy
  `eql_v2_encrypted` counterpart) instead of being replaced by a guess. A
  genuinely stale hint — one naming a column that is gone — still falls back to
  the naming convention as before.

- **`drop`'s refusal message prescribed the guess.** It told the user to re-run
  `backfill --encrypted-column <the guessed column>`. Following it recorded the
  guess as fact, so the next run resolved "by hint", walked past the refusal,
  and passed the coverage check vacuously — an unrelated but legitimately
  backfilled column is non-NULL on every row — then generated a live
  `DROP COLUMN` on the plaintext and exited 0. The message now asks for the
  column that actually encrypts the named one, and says explicitly not to record
  the guess.

The `unresolvedHint` refusal is scoped to tables that actually hold EQL v3
columns a guess could wrongly claim. A **pure-v2** table has none, so it still
falls through to the EQL v2 lifecycle exactly as before — including when
`encrypt backfill` recorded an `encryptedColumn` for it, which it does for v2
columns too.

Two cases DO newly exit 1, both deliberately:

- Any table with at least one EQL v3 column where the manifest records an
  `encryptedColumn` that exists but is not one of them — not only the
  v2-pair-plus-one-v3 shape. The recorded pairing is authoritative and
  disagrees with every candidate, so guessing past it is the bug.

- A column whose encrypted counterpart could only be identified **by
  elimination** — no recorded `encryptedColumn`, no `<col>_encrypted` name
  match, one EQL column left once the plaintext column itself is excluded.
  `cutover` now refuses this as `drop` already did. Note `.cipherstash/` is
  gitignored, so `migrations.json` is machine-local: a fresh clone or CI runner
  can hit this on a **pure-v3** table whose encrypted column is named
  unconventionally, where `cutover` previously exited 0 with "not applicable".
  Re-run `stash encrypt backfill --table T --column C --encrypted-column <name>`
  to record the pairing.
