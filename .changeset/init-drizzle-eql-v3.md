---
'stash': patch
---

`stash init --drizzle` installs EQL v3.

The Drizzle init flow used to provision a v2 database — the only
migration-generating install path at the time was v2-only — while the
`stash-drizzle` skill init copies into the same project documents the v3
`@cipherstash/stack-drizzle` surface (`types.*` domains, `Encryption`). The
user's agent would have authored v3 code against a v2 database.

Init's Drizzle flow now routes through `stash eql migration --drizzle`, so it
stays migration-first (the install lands in your Drizzle migration history and
ships to every environment via `drizzle-kit migrate`) while emitting v3 SQL.
The generated migration also carries the `cs_migrations` tracking schema, so one
`drizzle-kit migrate` covers everything `stash encrypt …` needs. If `drizzle-kit`
isn't installed or configured, init now reports EQL as not installed and points
at `stash eql migration --drizzle` rather than aborting the run.

The CLI installation and mutation surface is v3-only. Legacy v2 remains readable
and visible in diagnostics. Generate a checked-in install migration with
`stash eql migration --drizzle`.
