---
'@cipherstash/stack-supabase': minor
---

`encryptedSupabase` can now be constructed without a Postgres connection, and there is a new edge entry that runs it off Node.

**The rule: declare your schemas and it runs anywhere; omit them and we discover them for you, which needs a database connection and is therefore Node-only.**

Previously the wrapper always introspected the database to derive each column's encryption config from its Postgres domain. That made it unconstructible anywhere a TCP socket to Postgres is unavailable, and cost a second, more privileged credential even on Node — the caller already had an authenticated Supabase client and had to supply a `databaseUrl` as well.

- **Passing `schemas` with no database URL skips introspection entirely.** No connection, no `pg`, no `databaseUrl`.
- **New `@cipherstash/stack-supabase/wasm-inline` entry.** Identical wrapper, WASM engine. The package root statically imports the native engine (`@cipherstash/protect-ffi` and `@cipherstash/auth`, both Node-API), and a static import loads whether or not you encrypt anything — so an edge runtime needs a different entry, not a different code path. ESM-only, matching `@cipherstash/stack/wasm-inline`. Server-side only; not browser-safe (#804).
- **`DATABASE_URL` is now read through a guard.** On a runtime with no `process` global a bare `process.env.X` is a `ReferenceError`, not `undefined`, so the unguarded read threw during construction before declared mode could help.

**Existing callers are unaffected.** The gate is the database URL, not the presence of `schemas`: if a URL resolves — from `options.databaseUrl` or `DATABASE_URL` — introspection still runs, and a `schemas`-passing caller still gets the drift check that verifies their declaration against the real column domains. "Pass `databaseUrl` as well" is how you keep verification while declaring types.

What declared mode gives up, it gives up loudly rather than silently:

- **`select('*')` and bare `select()` are refused.** `allColumns` comes only from introspection, and an unexpanded `*` reaches PostgREST without the `::jsonb` casts encrypted columns need.
- **`from()` on an undeclared table throws**, naming the declaration rather than an introspection pass that never ran.
- **The drift check is absent**, so a wrong declared domain surfaces as a `23514` CHECK violation on the first write instead of at construction.
- **`queryDomainsRequired` is forced rather than detected**, since the installed EQL version is read by introspection. This is the fail-loud direction: correct on EQL >= 3.0.2, and on an older install the operand cast fails visibly instead of emitting an operator the database will not engage.
- **Passing `databaseUrl` to the `wasm-inline` entry is refused** — it carries no Postgres driver, and saying so beats ignoring the option.

Also fixed: a read awaited with no `.select()` call sent a raw `*` to PostgREST, bypassing the refusal that `select('*')` has always performed — so every encrypted column came back uncast. Both spellings of "give me everything" now behave identically.

The `pg` peer range moves from `>=8` to `>=8.16.3`, the floor at which `pg` works on Cloudflare via `pg-cloudflare`.
