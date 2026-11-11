---
'stash': patch
---

`stash encrypt drop` and `stash decrypt drop` now write the Drizzle migration to the directory drizzle-kit reports (the `out` in `drizzle.config.ts`) instead of scanning `--migrations-dir`. Previously, when the two differed, the SQL could be written over an older migration with the same name while drizzle-kit journaled an empty stub in the real `out`, so the DROP never shipped. When a scan fallback is needed it matches the exact `_<name>.sql` suffix and refuses to overwrite any file that is not a drizzle-kit scaffold (blank or comment-only), and `--migrations-dir` now warns when drizzle-kit wrote elsewhere.
