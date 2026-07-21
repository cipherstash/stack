---
'stash': patch
---

`stash init --drizzle` now installs EQL v3 instead of v2.

The Drizzle init flow pinned `--eql-version 2`, because `stash eql install
--drizzle` (the only migration-generating install path at the time) was
v2-only. That made `stash init --drizzle` the single flow that provisioned a v2
database — a bare `stash eql install`, and init for every other integration,
already defaulted to v3. It also contradicted the `stash-drizzle` skill init
copies into the same project, which documents the v3 `@cipherstash/stack-drizzle/v3`
surface (`types.*` domains, `EncryptionV3`) and would have the user's agent
author v3 code against a v2 database.

Init's Drizzle flow now routes through `stash eql migration --drizzle`, so it
stays migration-first (the install lands in your Drizzle migration history and
ships to every environment via `drizzle-kit migrate`) while emitting v3 SQL.
The generated migration also carries the `cs_migrations` tracking schema, so one
`drizzle-kit migrate` covers everything `stash encrypt …` needs. If `drizzle-kit`
isn't installed or configured, init now reports EQL as not installed and points
at `stash eql migration --drizzle` rather than aborting the run.

The v2 Drizzle path remains available for existing deployments via an explicit
`stash eql install --drizzle --eql-version 2`; that command's error message now
points at the v3 alternative instead of only suggesting `--eql-version 2`.
