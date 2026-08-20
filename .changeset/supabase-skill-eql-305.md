---
'stash': patch
---

Update the bundled agent skills for eql-3.0.5. `skills/stash-supabase`
re-states the PostgREST query-domain limitations against 3.0.5 (unchanged in
substance — the typed `eql_v3.query_*` operand requirement still stands), and
`skills/stash-postgres` drops one of the two places it claimed the CLI pins
`@cipherstash/eql` to an exact version — a claim that stopped being true when
EQL moved in-tree. The second copy goes in the same release, with the rest of
that skill's EQL source and issue pointers.
