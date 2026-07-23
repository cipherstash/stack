---
'stash': minor
'@cipherstash/wizard': minor
---

New bundled agent skill: `stash-indexing` — how to index EQL v3 encrypted
columns. Integrations that were otherwise correct shipped with no index on any
encrypted predicate because nothing in the installed skills said encrypted
columns *can* be indexed (#753). The skill covers the functional-index recipes
over the term extractors (`eql_v3.eq_term` / `ord_term` / `ord_term_ore` /
`match_term` / `to_ste_vec_query`) mapped to the `types.*` domains, what works
without superuser on Supabase and managed Postgres versus the ORE opclass
restriction, which domains are storage-only by design, the query shapes that
engage an index (`ORDER BY` sort-key and `GROUP BY` traps), building indexes on
large tables, an `EXPLAIN` verification checklist, and when to create indexes
during an encryption rollout (after backfill, before switching reads).

`stash init` / `stash impl` handoffs — and the `@cipherstash/wizard` skills
prompt — now install it for **every** integration (Drizzle, Supabase, Prisma
Next, plain PostgreSQL) — the gap is cross-cutting.
The existing per-integration skills gained pointers to it (including the
missing `stash-prisma-next` one-line purpose in the setup prompt, which
previously rendered "(no description)").
