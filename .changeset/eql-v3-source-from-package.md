---
'stash': patch
---

The EQL **v3** install SQL is now read from the `@cipherstash/eql` package at
runtime instead of a copy vendored into this repo. `@cipherstash/eql` becomes a
runtime dependency of `stash`, and a version bump now flows straight through — no
re-vendor step, no drift between the pin and the shipped bundle.

This removes ~44k lines of generated plpgsql from the repository (which had made
GitHub classify the whole repo as plpgsql — CIP-3518) along with the
`gen:eql-v3-sql` vendor script and its CI drift-check.

No behaviour change: v3 installs the same one-artifact bundle (which self-adapts to
non-superuser environments like Supabase), and the v2 path is unchanged.
