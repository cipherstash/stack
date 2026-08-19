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

One tradeoff is **not** loud, and is the declared-mode contract you have to hold yourself: **your declaration must cover every encrypted column of a table you query.** Nothing introspects, so a column carrying an `eql_v3` domain in the database but absent from `schemas` is treated as an ordinary plaintext column — a `select` naming it returns the raw EQL payload as data, and a filter on it sends the plaintext operand to PostgREST. The always-introspect path could not do this (undeclared columns were synthesized from their domains). Declare every encrypted column, or pass `databaseUrl` so introspection fills the gaps.

An ambient `DATABASE_URL` no longer overrules a declaration, and is consulted only by a build that could act on it: on the edge entry — which cannot introspect at all — it is never read, so a `DATABASE_URL` that happens to be set in the environment cannot break a declared-mode client. On the native entry, passing `schemas` without an explicit `databaseUrl` ignores the variable and warns that the declaration is unverified. The refusal of a `databaseUrl` on the edge entry now keys on the option you actually passed, so it can never fire for a value you did not write. Previously a stray variable silently exited declared mode — introspecting a database the caller never named on Node, and on the edge entry throwing "drop databaseUrl" about an option never passed.

**The edge entry adapts the WASM client rather than casting to it.** The two engines are not drop-in for each other, and every difference is silent at construction — the entry would have built a client happily while each query through it failed. `decryptModel` / `bulkDecryptModels` require the table on WASM and derive it from the payloads on native (both call sites now pass it, which native ignores); WASM operations are plain Results with no `.withLockContext()` or `.audit()`, so both are attached and throw a sentence naming the gap rather than a bare `TypeError`; and `bulkEncrypt` is deliberately not forwarded, selecting the supported per-term fallback instead of a mismatched signature. Lock context is a real capability gap on the WASM engine (cipherstash/stack#797) — failing loudly is the only honest option, since silently dropping the claim would write values any keyset holder could decrypt.

The edge entry's options are also typed for what it actually requires: `schemas` and a `WasmClientConfig` `config` are both mandatory (there is no `~/.cipherstash` to discover credentials from), and `databaseUrl` is absent from the type as well as refused at runtime. Previously the shared factory's erased config type let an edge caller omit credentials entirely and reach a `TypeError` from inside the engine.

