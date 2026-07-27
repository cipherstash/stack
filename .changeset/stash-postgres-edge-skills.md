---
'stash': minor
'@cipherstash/wizard': minor
'@cipherstash/stack': patch
---

Two new bundled agent skills for the integrations that don't use an ORM —
`stash-postgres` and `stash-edge` (#754).

Everything a raw-SQL or edge integration needed was reachable only from
`dist/*.d.ts` JSDoc, the Postgres catalog, or experiment: grepping the skills
`stash init` installs for `postgres-js|::jsonb::eql|sql.json|query_text_search`
returned a single hit, in an unrelated code comment.

**`stash-postgres`** — hand-written SQL over `pg` / `postgres-js`, no ORM. The
column-domain-to-query-domain operator matrix (which of `=`, `<>`, `<`, `>=`,
`@@`, `@>` each encrypted domain accepts, and against which `eql_v3.query_*`
operand), the storage-vs-query payload distinction, per-driver parameter
binding, recipes for equality / free-text / range / `ORDER BY` / JSON
containment / JSON field selectors, and the `information_schema` drift check.
Two failure modes get their mechanism spelled out: pre-stringifying a payload
on postgres-js double-encodes it into a jsonb *string* scalar, tripping the
domain CHECK with a message naming neither JSON nor encoding; and leaving an
operand as bare `jsonb` silently selects a different operator overload — one
that coerces to the *storage* domain and so rejects the ciphertext-free query
term. It also scopes itself against the two things a hand-written-SQL reader
is otherwise left to infer: **CipherStash Proxy** (where you write plaintext
SQL and none of the skill applies — the `usesProxy` fork `stash init` already
asked about), and the provenance of the operator surface itself (the EQL
bundle from `cipherstash/encrypt-query-language`, version-checkable with
`SELECT eql_v3.version()`, and where operator gaps should be filed). Its
domain and operator tables are explicitly marked as a snapshot of a versioned
surface, with a ranked list of authorities to confirm current types against —
the EQL skill first, then the generated `@cipherstash/eql` types and install
SQL, both of which need only `node_modules` and no database.

**`stash-edge`** — the `@cipherstash/stack/wasm-inline` entry for Deno,
Supabase Edge Functions, Cloudflare Workers, and Bun. Import specifier per
runtime, the four mandatory `CS_*` variables and minting them with
`stash env`, how the WASM client surface differs from the native typed client
(no `.audit()`, per-item bulk shape, a required `table` argument on
`decryptModel` / `bulkDecryptModels`, ESM-only), and the auth-strategy
`Result` that must be unwrapped before it reaches `config.authStrategy`. It
also separates the two mechanisms behind identity-bound encryption, which are
routinely conflated: an auth strategy decides *who the client is*, a lock
context decides *which key the value is encrypted under*, and a strategy on
its own writes data that is not identity-bound.

Both carry **the credential-identity rule**, a silent data-loss footgun now
also stated in `stash-cli` (under `env` and `encrypt backfill`) and
`stash-supabase`: EQL index terms derive from the ZeroKMS client key, so rows
written under one credential and queried under another decrypt correctly and
never match a query, with no error.

`stash-encryption` now states that the two entries' schema types **do not
interchange** — their column classes carry private fields, so TypeScript
compares them nominally and rejects a shared schema module in both directions.
It works at runtime, which makes a type assertion the tempting fix; the
guidance is to author the schema against exactly one entry instead.

`stash init` / `stash impl` handoffs and the `@cipherstash/wizard` skills
prompt install both skills for the `postgresql` and `supabase` integrations.
Drizzle and Prisma Next get cross-links from their own skills instead, since
those integrations emit correctly-typed operands themselves.

Also fixes the `@cipherstash/stack/wasm-inline` module JSDoc, which showed
`OidcFederationStrategy.create(...)`'s `Result` being passed straight to
`config.authStrategy` without unwrapping — the same JSDoc the raw-SQL surface
was being reverse-engineered from.
