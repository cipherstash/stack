---
'stash': patch
---

New `stash-managed-platforms` skill: implementing CipherStash on a managed AI app platform (Lovable, v0, Bolt, Replit).

These platforms share a shape — no shell the developer controls, an edge/Workers runtime, a database role that is not `postgres`, and schema changes only through the platform's own migration tool — and every one of those changes the setup. The skill covers the WASM entry, running `stash auth login --json` headlessly in an ephemeral sandbox, minting `CS_*` with `stash env`, installing EQL as a non-`postgres` role (including generating a migration instead of installing directly), which predicates survive PostgREST, and why `encryptedSupabase` cannot be constructed inside a Worker.

The costly one is first, because it decides whether anyone gets any further: **use `@cipherstash/stack` with the `@cipherstash/stack/wasm-inline` entry.** `@cipherstash/protect` is the deprecated predecessor, and reasoning from its `@cipherstash/protect-ffi` dependency to "there is no way to run this on an edge runtime" is a wrong conclusion drawn from the wrong package. That dead end cost an agent a full turn on a real project before it found `stash`. The same correction is now stated in `stash-edge`'s entry table, where an agent comparing runtimes will hit it.

Two things were also lifted above the fold in `stash-supabase`: a pointer to the new skill, and a one-line summary of what does and does not survive PostgREST (`eq`/`neq`/`in`/`match()` and the range filters do; encrypted `matches()` and JSON containment do not). The full treatment was correct but ~500 lines down, which is not where a time-pressured agent finds it.

Registered for the `supabase` and `postgresql` integrations in both the CLI and wizard skill maps, so it installs into `.claude/skills` / `.codex/skills` and inlines into `AGENTS.md` on those paths.
