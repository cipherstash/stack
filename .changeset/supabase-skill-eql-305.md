---
'stash': patch
---

Update the bundled agent skills for eql-3.0.5. `skills/stash-supabase`
re-states the PostgREST query-domain limitations against 3.0.5 (unchanged in
substance — the typed `eql_v3.query_*` operand requirement still stands), and
`skills/stash-postgres` drops a claim that the CLI pins `@cipherstash/eql` to
an exact version, which stopped being true when EQL moved in-tree.
