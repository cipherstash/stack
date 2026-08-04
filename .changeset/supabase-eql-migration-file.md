---
'stash': minor
---

Add `stash eql migration --supabase`, so an EQL v3 install survives `supabase db reset` (#613).

Supabase projects previously had only `stash eql install --supabase`, which applies the SQL directly to a running database. `supabase db reset` — the ordinary local development loop — drops that database and replays `supabase/migrations/`, so the install was wiped and the next query failed with `type "eql_v3_encrypted" does not exist`. There was no supported way to get EQL into the migrations directory.

`stash eql migration --supabase` now writes `supabase/migrations/<timestamp>_cipherstash_eql.sql`, carrying the EQL v3 bundle, the `anon` / `authenticated` / `service_role` grants, and the `cipherstash.cs_migrations` tracking schema — so one `supabase db reset` provisions everything `stash encrypt` needs. The file is timestamped at generation time, so it sorts after everything already applied and pushes without `--include-all`. A second run exits rather than adding a duplicate install; `--force` regenerates the existing one in place, and `--out <dir>` targets a non-default migrations directory.

`--supabase` keeps its existing meaning alongside `--drizzle` (append the role grants to the Drizzle migration); only a bare `--supabase` selects the new emitter.

`stash init --supabase` now generates that migration instead of installing directly, when the project has local `supabase/` scaffolding — a hosted project without it still installs directly. Re-running init over a project that already has an install migration reports it and moves on, rather than treating the duplicate refusal as a failed setup. Its next steps no longer tell you to run `eql install --supabase` and then `supabase db reset`, which was the exact sequence that destroyed the install.

Also corrects the remote apply command across the Supabase guidance: a bare `supabase migration up` targets the local database, so the instructions now say `supabase db push`.

Also corrects the `eql install --migration` removal message, which pointed every Supabase user at `--drizzle`.
