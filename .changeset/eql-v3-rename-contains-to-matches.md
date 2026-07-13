---
'@cipherstash/stack-drizzle': minor
'@cipherstash/stack-supabase': minor
---

Rename the EQL v3 encrypted free-text operator `contains()` → `matches()` (#617).

Encrypted free-text search is fuzzy bloom-filter token matching — order- and
multiplicity-insensitive and one-sided (a `true` may be a false positive) — not
containment. The name `contains()` promised substring/containment semantics it
never had. It is renamed to `matches()` on the encrypted surface; `contains()` is
kept for genuine, exact containment:

- **Drizzle** (`@cipherstash/stack-drizzle/v3`): `matches()` = bloom free-text on
  `text_match`/`text_search` columns; `contains()` = exact encrypted-JSON `@>` on
  `types.Json` (ste_vec) columns.
- **Supabase** (`@cipherstash/stack-supabase`): `.matches()` = encrypted free-text;
  `.contains()` = native jsonb/array `@>` on plaintext columns (and throws on an
  encrypted column, pointing to `matches()`).

Also on the Supabase v3 surface, `like()`/`ilike()` on an encrypted column are no
longer rejected — they are delegated to `matches()` as a best-effort compatibility
shim. This is APPROXIMATE (fuzzy, case-insensitive, one-sided; anchoring and
wildcards are not honored): surrounding `%` are stripped, an internal `%` or any
`_` is rejected, and a one-time warning is emitted. A plaintext column keeps real
SQL LIKE.

Breaking: encrypted `contains()` callers must migrate to `matches()`. The
encrypted operator has not shipped in a stable release (it lands via the EQL v3
work), so there is no deprecation alias.
