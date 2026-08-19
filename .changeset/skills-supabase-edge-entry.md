---
'stash': patch
---

Skills: `encryptedSupabase` can now be constructed in a Worker, so the guidance that said it could not has been corrected.

`skills/stash-managed-platforms` replaces its "cannot be constructed in a Worker" section with the two things that must both be right — import `@cipherstash/stack-supabase/wasm-inline` rather than the package root, and declare your `schemas` so nothing introspects — plus what declared mode gives up (`select('*')`, `from()` on an undeclared table, and the drift check) and how to keep the drift check on Node by passing `databaseUrl` as well.

`skills/stash-supabase` and `skills/stash-edge` gain the same correction where each would be read: the above-the-fold managed-platform callout, and the runtime-entry table respectively.
