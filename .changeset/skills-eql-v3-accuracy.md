---
'stash': patch
---

Correct stale EQL v3 guidance in the bundled agent skills.

`@cipherstash/migrate` and the `stash encrypt *` commands gained EQL v3 support
(cipherstash/stack#648, now closed), but the shipped skills still told readers the
rollout tooling was v2-only. Since these skills are copied into customer repos, the
stale text steered users away from v3 and toward workarounds they no longer need.

- **`stash-drizzle`, `stash-supabase`** — replaced the "v3 not supported end-to-end"
  callouts with an accurate EQL version note: the tooling auto-detects a column's
  generation from its Postgres domain type, and the two lifecycles differ at the end.
  v3 is `backfill → switch the app to the encrypted column by name → drop` with no
  cut-over rename; v2 keeps the `stash encrypt cutover` rename plus config promotion.
- **`stash-supabase`** — removed the "Interim path until #648: the v2 encrypted twin"
  section; a v2 twin is no longer needed to get CLI-managed backfill.
- **`stash-drizzle`, `stash-supabase`** — the drop step now documents that
  `stash encrypt drop` targets the *original* column under v3 (there is no
  `<col>_plaintext`, since nothing was renamed) and `<col>_plaintext` under v2.
- **`stash-cli`** — corrected the documented `EQLInstaller` default: `eqlVersion`
  defaults to `3`, not `2`, matching the `--eql-version` CLI default. Also reworded
  the v2 cut-over known-gap note, which cited cipherstash/stack#585 as open tracking
  when it was resolved by making v3 the default.
