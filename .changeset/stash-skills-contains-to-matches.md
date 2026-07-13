---
'stash': patch
---

Update the `stash-drizzle` and `stash-supabase` skills for the EQL v3
`contains()` → `matches()` rename (#617): the encrypted free-text operator is now
`matches()` (fuzzy bloom token matching), `contains()` is reserved for exact
containment, and Supabase `like()`/`ilike()` on encrypted columns are documented
as an approximate compatibility shim delegating to `matches()`. Skills ship inside
the `stash` tarball, so they must track the adapter surface.
