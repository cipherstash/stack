---
'@cipherstash/stack-supabase': patch
---

Correct the runtime story in the TSDoc that ships as `.d.ts`.

Three claims a user sees on hover were wrong:

- `makeEncryptedSupabase` said "Declare your schemas and it runs anywhere; omit
  them and we discover them for you, which needs a database connection and is
  therefore Node-only." Declaring `schemas` does skip introspection entirely —
  no Postgres connection, no `pg`, no `databaseUrl` — but it does not make the
  default entry edge-capable. **The entry point decides where the wrapper runs;
  `schemas` decides only whether Postgres is involved.**
- The default entry's doc named `@cipherstash/protect-ffi` as the Node-API
  binary loaded on import. It is the one package in that graph that
  deliberately does not load on import; the module-evaluation-time load belongs
  to `@cipherstash/auth`.
- `./wasm-inline`'s doc called introspection "half of what made the default
  entry Node-only". The engine is what makes it Node-only, and its emitted
  bundle also carries an `import("pg")` specifier a bundler resolves at build
  time. Introspection is a separate axis.

Documentation only — no runtime behaviour changes.
