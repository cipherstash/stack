---
'stash': minor
---

EQL installs no longer abort on managed platforms whose database role is not `postgres`, and a new `stash eql preflight` command reports role capability before anything is attempted.

- `stash eql install` (and `eql upgrade`) now run the EQL v3 bundle in its own transaction and the Supabase role grants after it commits, so a grants failure can no longer roll back a working install. When the connecting role is not a member of `postgres` (e.g. Lovable's `sandbox_exec`), the three owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements are skipped and the install completes without them — they are optional (they only cover EQL objects `postgres` might later create outside stash tooling, and stash re-grants every object on each install/upgrade); the SQL is printed as "Optional SQL — requires postgres" for operators who want it. Every plain `GRANT` still runs. Previously that single refused statement rolled back the entire install (~194 functions).
- New read-only `stash eql preflight` (`--json` for agents): reports `current_user`, superuser, membership of `postgres` (guarded for databases with no `postgres` role), `CREATE` on the database and on `public`, `pgcrypto`, and whether the EQL v3 schemas exist — each blocked row naming the statement it blocks. Exits 1 on blocking gaps; membership of `postgres` never blocks. The same check now runs at the head of `eql install`.
- Install failure messages now state recoverability: a bundle failure says nothing was applied (rolled back); a grants failure says the install itself was kept.
- Library surface: `EQLInstaller.checkPermissions()` is replaced by `EQLInstaller.preflight()` (richer `PreflightResult`), and `install()` now returns `InstallResult` with the deferred SQL, if any. The exact `SUPABASE_PERMISSIONS_SQL_V3` block is unchanged byte-for-byte; new exports expose its immediate (`SUPABASE_IMMEDIATE_GRANTS_SQL_V3`) and owner-scoped (`SUPABASE_DEFAULT_PRIVILEGES_SQL_V3`) halves.
