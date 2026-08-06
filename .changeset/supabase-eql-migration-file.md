---
'stash': minor
---

Add `stash eql migration --supabase`, so an EQL v3 install survives `supabase db reset` (#613).

Supabase projects previously had only `stash eql install --supabase`, which applies the SQL directly to a running database. `supabase db reset` — the ordinary local development loop — drops that database and replays `supabase/migrations/`, so the install was wiped and the next query failed with `type "eql_v3_encrypted" does not exist`. There was no supported way to get EQL into the migrations directory.

`stash eql migration --supabase` now writes `supabase/migrations/<timestamp>_cipherstash_eql.sql`, carrying the EQL v3 bundle, the `anon` / `authenticated` / `service_role` grants, and the `cipherstash.cs_migrations` tracking schema — so one `supabase db reset` provisions everything `stash encrypt` needs. The file is timestamped at generation time, so it sorts after everything already applied and pushes without `--include-all`. A second run exits rather than adding a duplicate install; `--force` regenerates the existing one in place.

The command now warns when the migrations directory already holds EQL-referencing migrations that sort *before* the install it is about to write. A project that ran `stash eql install` directly and then added `public.eql_v3_*` columns against the live database gets an install stamped today — after those migrations — and `supabase db reset`, which replays in version order with no dependency awareness, then fails with `type "eql_v3_text_search" does not exist`. The warning names the specific files and the remedy (rename the install below the earliest of them; a back-dated push to a remote with history needs `supabase db push --include-all`). It fires on `--dry-run` too, and nothing is renamed automatically — the ordering of someone else's deployed history is not ours to change silently.

`--force`'s follow-up guidance was wrong and is now correct. It said to re-apply with `supabase db reset` (local) **or `supabase db push` (remote)**, but a push never re-applies a rewritten migration: the Supabase CLI decides what is pending by comparing versions, never file content, so an in-place rewrite keeping its version is skipped and push reports `Remote database is up to date.` The remote recipe is now `supabase migration repair --status reverted <version>` (tracking table only — it applies no SQL) followed by `supabase db push --include-all`, the flag being required because the reverted version is a gap in the middle of remote history. The warning also names the hazard it never mentioned: the EQL bundle opens with `DROP SCHEMA IF EXISTS eql_v3 CASCADE`, so re-applying drops every index, constraint, and RLS policy that references `eql_v3` / `eql_v3_internal` — free on a fresh `db reset`, destructive on a populated remote.

`--out` on a bare `--supabase` now warns. The Supabase CLI's migrations directory is not configurable — `supabase db reset` and `supabase db push` read `<project>/supabase/migrations` and nothing else, `config.toml` has no key for it, and `--workdir` relocates the whole `supabase/` directory rather than this subdirectory — so an install written elsewhere is never applied, which is the original bug relocated. The flag still writes the file (a project may apply that directory through its own tooling) but names the consequence, on `--dry-run` too. `--out` alongside `--drizzle --supabase` is unaffected: there it is drizzle-kit's output directory.

`--supabase` keeps its existing meaning alongside `--drizzle` (append the role grants to the Drizzle migration); only a bare `--supabase` selects the new emitter.

`stash init --supabase` now generates that migration instead of installing directly, when the project has local `supabase/` scaffolding — a hosted project without it still installs directly. Re-running init over a project that already has an install migration reports it and moves on, rather than treating the duplicate refusal as a failed setup. Its next steps no longer tell you to run `eql install --supabase` and then `supabase db reset`, which was the exact sequence that destroyed the install.

`stash init`'s EQL summary line now distinguishes the migration it wrote from one it merely found. A re-run over an existing install migration says "EQL migration **already present**" instead of "EQL migration generated" — same apply guidance, same successful exit, but no claim about work the run did not do.

`stash init`'s EQL prompt now names the action for the route it is actually on. On the migration-first routes it asks whether to generate a migration (naming `supabase/migrations/` or your Drizzle migrations folder) rather than whether to install into your database, which described the wrong action on both. Declining is fixed the same way: the retry hint is now `stash eql migration --supabase` / `--drizzle` on those routes instead of `stash eql install`, which on Supabase would reinstate the very bug above.

Also corrects the remote apply command across the Supabase guidance: a bare `supabase migration up` targets the local database, so the instructions now say `supabase db push`.

Also corrects the `eql install --migration` removal message, which pointed every Supabase user at `--drizzle`.
