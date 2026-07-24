---
'stash': patch
'@cipherstash/migrate': patch
'@cipherstash/stack': patch
---

Correct shipped documentation that claimed the tooling detects a column's EQL
**v2** generation. It does not, and has not since `classifyEqlDomain` dropped v2:
detection is one-sided — a `public.eql_v3_*` Postgres domain classifies as **v3**,
and anything else (a plaintext column, or a legacy `eql_v2_encrypted` one)
classifies as *unknown* and falls through to the **v2** lifecycle. The v2 path is
reached by fallback, not by detection, and a v2 column records no `eqlVersion` in
`.cipherstash/migrations.json`, so `stash encrypt status` reports no version for
it.

- `skills/stash-supabase/SKILL.md` said the CLI "still auto-detects a v2 column"
  (twice, once inside the "Stay on v2 for now" bullet — exactly the case it got
  wrong) and that `stash encrypt drop` picks its target from a version the CLI
  "auto-detects". All three now describe the one-sided rule, matching the correct
  wording already in the same file's EQL version note. This skill is copied into
  customer repos by `stash init`, so the wrong version of it was being installed
  as guidance.
- `packages/migrate/README.md` documented `detectColumnEqlVersion(client, table,
  column)` as returning `2`, `3`, or `null`. It cannot return `2` — the return
  type is now stated as `3` or `null`, with what a `null` means for the caller.
  The lifecycle intro no longer presents the v2 ladder as a detection result.
- `packages/stack/README.md`'s Supabase example imported and called
  `encryptedSupabaseV3`, the `@deprecated` alias, contradicting the same file's
  package table and v3-only note. It now uses `encryptedSupabase`.

Documentation only — no behaviour change.
