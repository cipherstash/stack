---
"stash": patch
---

Correct the bundled `stash-supabase` agent skill. The skills directory ships
inside the `stash` tarball and is copied into the user's `.claude/skills/` /
`.codex/skills/` (or inlined into `AGENTS.md`) at handoff time, so a stale skill
becomes stale guidance in the user's project.

- **`order()` on Supabase.** The skill said `ORDER BY` on encrypted columns is
  unsupported on Supabase. That is still true for EQL v2 (operator families need
  superuser), but v3 `order()` now works on OPE-backed ordering columns
  (`*_ord`, `text_ord`, `text_search`) via the `col->op` jsonb path. Scoped the
  v2 statement to v2, documented the v3 support matrix (ORE-only ordering
  columns and columns with no ordering term are rejected with a clear error),
  and corrected the typed-narrowing note (`order()` accepts plaintext **and**
  OPE ordering columns, not plaintext only).
- **Exports.** Corrected the v3 type list to the real surface:
  `EncryptedSupabaseV3Options` (not `EncryptedSupabaseV3Config`), plus
  `TypedEncryptedSupabaseV3Instance`, `EncryptedQueryBuilderV3Untyped`, and
  `V3FreeTextSearchableKeys`, keeping `EncryptedSupabaseResponse` /
  `EncryptedSupabaseError` and `V3FilterableKeys`.
- **Dropped the `include_original: false` substring workaround.** `protect-ffi`
  ignores the flag, so setting it does not enable substring search; the skill
  now states the honest limitation (`contains()` matches exact values, not
  general substrings — tracked upstream in EQL).
