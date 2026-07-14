---
'stash': patch
---

Update the bundled `stash-drizzle`, `stash-supabase`, and `stash-encryption` agent
skills (and the stack README / Supabase reference doc) for the adapter package
split: the Drizzle and Supabase integrations import from `@cipherstash/stack-drizzle`
(+ `/v3`) and `@cipherstash/stack-supabase` respectively, installed alongside
`@cipherstash/stack`, rather than from `@cipherstash/stack/{drizzle,supabase,eql/v3/drizzle}`
subpaths. Skills ship inside the `stash` tarball, so the stale import paths would
otherwise become wrong guidance in a user's project.
