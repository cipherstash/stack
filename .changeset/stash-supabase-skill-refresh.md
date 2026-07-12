---
"stash": patch
---

Rewrite the bundled `stash-supabase` agent skill to be EQL v3-first. The skills
directory ships inside the `stash` tarball and is copied into the user's
`.claude/skills/` / `.codex/skills/` (or inlined into `AGENTS.md`) at handoff
time, so a stale skill becomes stale guidance in the user's project. The skill led
with the v2 `encryptedSupabase` wrapper and stranded v3 at the bottom; v3 is now
the current surface and the focus.

- **v3 leads.** `encryptedSupabaseV3` is documented first: connect-time schema
  introspection (no schema argument to `from()`), native `public.eql_v3_*` column
  domains, `select('*')`, and the full query/insert/update/select surface in v3
  terms. Declaring `schemas` is presented as **optional** (compile-time types +
  startup verification) rather than required — introspection already knows every
  column's domain.
- **Free-text search is `contains()`, not `like`/`ilike`.** `like`/`ilike` are
  rejected on encrypted v3 columns. Corrects the previous claim that `contains()`
  matched only exact values: it matches substrings of at least the tokenizer's
  `token_length` (3 characters); shorter terms are rejected rather than matching
  every row.
- **`order()` works on OPE-backed v3 ordering columns** (`*_ord`, `text_ord`,
  `text_search`) via the `col->op` jsonb path; ORE-only ordering columns and
  columns with no ordering term are rejected with a clear error. (v2 still cannot
  order encrypted columns on Supabase.)
- **Migration guide rewritten for v3** — native domains, direct-only install (no
  `supabase/migrations/` file; re-run after `supabase db reset`), and no EQL
  configuration table (so no `db push`/`db activate` in the v3 flow).
- **v2 relegated to a slim "Legacy: EQL v2" section** enumerating the differences
  (`eql_v2_encrypted` storage, required schema, `like`/`ilike`, no encrypted
  ordering, `--migration` install), since `encryptedSupabase` still ships.
- Corrected the exported-types list to the real v3 surface and documented the
  `error.encryptionError`-always-undefined caveat.
