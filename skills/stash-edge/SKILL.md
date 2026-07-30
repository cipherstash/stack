---
name: stash-edge
description: Run CipherStash encryption on edge and non-Node runtimes with the `@cipherstash/stack/wasm-inline` entry — Deno, Supabase Edge Functions, Cloudflare Workers, and Bun. Covers the import specifier per runtime, which `CS_*` variables are mandatory and minting them with `stash env`, how keysets and credentials interact on the edge (what must match is the keyset — `stash-zerokms` is canonical), how the WASM client surface differs from the native typed client, why the entry is server-side only and never belongs in a browser bundle, and how one EQL v3 schema module is shared across both entries. Use when adding encryption to a Supabase Edge Function, a Worker, or a Deno service; when a native module fails to load in a deployed runtime; when wiring `CS_*` secrets into an edge deploy; or when encrypted search returns zero rows on the edge but works locally.
---

# Encryption on the Edge (WASM entry)

`@cipherstash/stack` has two runtime entries. The default one binds a
Node-API native module and must be loaded by Node's own `require`.
**`@cipherstash/stack/wasm-inline` is the entry for
everywhere else** — it carries the WASM build of the same engine as a base64
blob inside the JS, so there is no native binding, no separate `.wasm` fetch,
and nothing for a bundler to externalise.

This skill covers that entry and the deployment shape around it. It is EQL v3
throughout. For the SQL that actually queries the encrypted columns — the
predicate forms and driver binding rules — see `stash-postgres`; edge functions
almost always talk to Postgres over a raw driver, so the two are usually read
together.

## When to Use This Skill

- Adding encryption to a Supabase Edge Function, Cloudflare Worker, Deno
  service, or Bun app.
- A deployed runtime fails to load the native module (`protect-ffi`), or a
  bundler chokes trying to include it.
- Wiring `CS_*` credentials into an edge deploy, or minting them at all.
- Encrypted search works locally but returns **zero rows** in the deployed
  function — see [Keysets and Credentials](#keysets-and-credentials-when-search-returns-zero-rows).
- A schema module shared with Node tooling fails to typecheck against the
  edge client.

## Choosing the Entry

| Runtime | Entry | Why |
|---|---|---|
| Node server, Next.js server code | `@cipherstash/stack` (+ `/v3`) | Native NAPI is faster; the native module must be excluded from bundling — see the [bundling guide](https://cipherstash.com/docs/stack/deploy/bundling) |
| Supabase Edge Functions | `@cipherstash/stack/wasm-inline` | Deno, V8-only, no native modules |
| Cloudflare Workers | `@cipherstash/stack/wasm-inline` | V8 isolate, no native modules |
| Deno (any) | `@cipherstash/stack/wasm-inline` | No NAPI under Deno's default permissions |
| Bun | `@cipherstash/stack/wasm-inline` | Works, and avoids native-module resolution differences |
| Anywhere bundling server code | `@cipherstash/stack/wasm-inline` | Bundles cleanly; nothing to externalise |

**The Supabase adapter has its own edge entry.** If you are using
`@cipherstash/stack-supabase`, import
`@cipherstash/stack-supabase/wasm-inline` (not the package root, which pulls
the native engine) and **declare your `schemas`** — the adapter's default
behaviour is to introspect the database for its column config, which needs a
Postgres connection. Declaring skips it. Those `schemas` can be authored from
either `@cipherstash/stack/eql/v3` or `@cipherstash/stack/wasm-inline` — both
entries resolve one declaration of the column classes, so the tables are
interchangeable. See "Schema Modules Cross Entries" below, plus
`stash-supabase` and `stash-managed-platforms`.

**`@cipherstash/protect` is not one of the options.** It is the deprecated
predecessor of `@cipherstash/stack`; its native `@cipherstash/protect-ffi`
dependency will not load in any of the runtimes above. Reasoning from *that*
package's dependency tree to "CipherStash cannot run on the edge" is a wrong
conclusion drawn from the wrong package — it has already cost one agent a
full turn on a hosted platform. The row you want is `wasm-inline`. (On a
managed AI platform specifically — Lovable, v0, Bolt, Replit — see
`stash-managed-platforms`.)

**The WASM entry is ESM-only.** Its `exports` map has an `import` condition
and no `require` — deliberately, since the runtimes it targets are ESM. A CJS
`require('@cipherstash/stack/wasm-inline')` will not resolve. Node consumers
that need it must be ESM (`"type": "module"` or `.mjs`).

## Importing It

### Supabase Edge Functions / Deno — `npm:` specifier

The Edge runtime resolves `npm:` specifiers at function start; there is no
build step.

```ts
import {
  Encryption, encryptedTable, types, isEncrypted,
} from 'npm:@cipherstash/stack@1.1.1/wasm-inline'
```

**Pin an exact version.** Deno caches by specifier, so an unpinned import
drifts between deploys — pin, and bump the pin deliberately. Check what is
current with `npm view @cipherstash/stack dist-tags`.

### Deno with an import map

For a project with a `deno.json`, map the specifier once and import the bare
name everywhere:

```jsonc
{
  "imports": {
    "@cipherstash/stack/wasm-inline": "npm:@cipherstash/stack@1.1.1/wasm-inline"
  }
}
```

```ts
import { Encryption, encryptedTable, types } from '@cipherstash/stack/wasm-inline'
```

> **No `--allow-ffi` needed.** The whole point of this entry is that nothing
> native loads. If a Deno process running this entry ever demands an FFI
> permission, something has resolved the native entry instead — check the
> import path before granting anything.

### Cloudflare Workers / Bun / bundlers — normal install

```bash
npm install @cipherstash/stack
```

```ts
import { Encryption, encryptedTable, types } from '@cipherstash/stack/wasm-inline'
```

No `externals`, no `nodeExternals`, no `serverExternalPackages` entry. If a
build config already externalises the native module for the default entry,
that config does not apply here and can be left alone.

## Credentials

The edge client is passed its credentials explicitly. There is no credential
discovery: `~/.cipherstash` does not exist in a Worker or an Edge Function
container, and there is no device-code login to fall back on.

`clientId` and `clientKey` are always required. Past those, `config` is a
union: the **access-key path** below adds `workspaceCrn` +
`accessKey` — the four `CS_*` values `stash env` mints — or you pass a
pre-built `config.authStrategy`, which already carries the CRN and so needs
neither `workspaceCrn` nor `accessKey` (see `config.authStrategy` below).

> [!IMPORTANT]
> **Server-side only — this entry never goes in a browser bundle.**
> `clientKey` is a workspace secret, and it is required on *every* auth path,
> including `authStrategy` (OIDC federation): the core loads it as encryption
> key material *before* it ever calls the strategy, so per-user federation
> does not stand in for it. That is why there is no `browser` export
> condition, and there will not be one until the core changes
> ([#804](https://github.com/cipherstash/stack/issues/804)). Every runtime
> this entry targets is a server — Deno, a Worker, Bun — not a page.

```ts
const client = await Encryption({
  schemas: [users],
  config: {
    workspaceCrn: Deno.env.get('CS_WORKSPACE_CRN')!,
    accessKey:    Deno.env.get('CS_CLIENT_ACCESS_KEY')!,
    clientId:     Deno.env.get('CS_CLIENT_ID')!,
    clientKey:    Deno.env.get('CS_CLIENT_KEY')!,
  },
})
```

Read them from the platform's environment accessor — `Deno.env.get(...)` on
Deno/Supabase, the `env` binding argument on Workers, `process.env` on Bun.

### Minting them: `stash env`

```bash
stash env --name my-app-prod            # print the four vars to stdout
stash env --name my-app-prod --write    # write .env.production.local (mode 0600)
stash env --name edge-dev --write .env.local
```

This creates a fresh ZeroKMS client **and** a CipherStash access key from your
local `stash auth login` session. Things that matter here:

- **The access key is shown exactly once.** Pipe it straight into the secret
  store; it cannot be re-revealed.
- **Stdout is pipe-clean** — only the dotenv block goes to stdout, so
  `stash env --name x > prod.env` and pipes into secret-store CLIs are safe.
- Each run mints a **new** credential, and duplicate names are rejected. Use a
  distinct `--name` per environment.
- `CS_CLIENT_KEY` and `CS_CLIENT_ACCESS_KEY` are secrets. Never commit them;
  put placeholder names in `.env.example` instead.

### Getting them into the runtime

```bash
# Supabase — local
supabase functions serve --env-file .env.local my-function

# Supabase — deployed
stash env --name my-app-prod --write .env.production.local
supabase secrets set --env-file .env.production.local

# Cloudflare Workers
wrangler secret put CS_CLIENT_KEY      # repeat per variable

# Vercel / other platforms
vercel env add CS_CLIENT_KEY production
```

## Keysets and Credentials (when search returns zero rows)

An earlier version of this section described a "credential-identity rule":
index terms deriving from the ZeroKMS client key, so rows written under one
credential would decrypt but silently never match a query. **That model is
wrong.** The scoping unit is the **keyset**, and `stash-zerokms` is the
canonical skill for it. What actually holds:

- Search terms are produced with a per-**keyset** index key. Every client
  **bound** to the keyset derives the *same* index key, so rows written by
  one credential match queries from another — different `CS_CLIENT_ID` /
  `CS_CLIENT_KEY` pairs interoperate fully as long as both clients resolve
  to the same keyset.
- The routing is asymmetric (`stash-zerokms` has the full model): encrypt
  and query always use the client's **bound** keyset — unreachable (no
  grant, revoked, disabled) means client construction fails loudly at the
  index-key load — while **decrypt follows each payload's keyset**, subject
  to grants, with an ungranted payload failing loudly (ZeroKMS 404).
- The old cautionary scenario — `stash encrypt backfill` from a laptop, then
  querying from an Edge Function with `stash env`-minted values — is fine
  when both clients resolve to the same keyset (the common case: both
  created against the workspace default). If they resolve to *different*
  keysets, how it fails depends on grants: no grant across them and decrypt
  fails loudly too; but a reader *granted* the writer's keyset while bound
  to its own decrypts fine and **silently searches the wrong keyspace —
  zero rows, no error**. Watch the keyset-less nuance from `stash-zerokms`:
  an operation with no explicit keyset resolves to **that client's default
  keyset**, so two clients created against different keysets don't share a
  keyspace even in the same workspace.

**If decrypt works but a query returns zero rows, it is never the credential
strings.** Check, in order: the reader's bound keyset against the writer's
(`stash-zerokms`), the operand cast / predicate form (`stash-postgres`), and
that the extractor index exists and is used (`stash-indexing`).

Environment hygiene still matters, for the reasons `stash-auth` and
`stash-deployment` give: mint one credential set per environment with
`stash env`, and don't point laptop profile credentials at production data.

## The Client Surface

`Encryption` from the WASM entry. **Both entries name the factory
`Encryption`**, so the import path is the only thing that distinguishes them —
which makes a stray `import { Encryption } from '@cipherstash/stack'` easy to
miss and confusing to debug, because the two clients take different config and
different bulk shapes. Check the specifier first whenever an edge client
behaves unexpectedly.

Every fallible method returns the same `{ data } | { failure }` Result
contract as the native client; unwrap before use.

```ts
const enc = await client.encrypt('alice@example.com', { table: users, column: users.email })
if (enc.failure) throw new Error(enc.failure.message)

const dec = await client.decrypt(enc.data)
if (dec.failure) throw new Error(dec.failure.message)
```

Available: `encrypt`, `decrypt`, `isEncrypted`, `encryptQuery`,
`encryptQueryBulk`, `bulkEncrypt`, `bulkDecrypt`, `encryptModel`,
`decryptModel`, `bulkEncryptModels`, `bulkDecryptModels`.

### How it differs from the native typed client

| | Native (`@cipherstash/stack`) | WASM (`@cipherstash/stack/wasm-inline`) |
|---|---|---|
| Factory | `Encryption({ schemas })` | `Encryption({ schemas, config })` — same name, different module |
| Schema authoring | `encryptedTable` / `types` from `@cipherstash/stack/v3` | the entry's own re-exports — interchangeable with the native ones (see below) |
| Config | discovered from env / `~/.cipherstash` | passed explicitly — `clientId` + `clientKey`, then either `workspaceCrn` + `accessKey` or a pre-built `authStrategy` (see below) |
| Typing | signatures derived from the schema | schema-aware, but not the full typed client |
| `.audit()` | chainable on operations | **not available** |
| `.withLockContext()` | chainable on operations | **not available** — see below |
| `bulkEncrypt` shape | `(plaintexts, { table, column })`, `{ id, plaintext }` envelopes | per-item `{ plaintext, table, column }`, plain index-aligned array |
| `decryptModel` / `bulkDecryptModels` | `(model, table, lockContext?)`, **plus** a table-less `(model)` overload for legacy rows | `(model, table)` only — the table is **required** |
| Module format | ESM + CJS | **ESM only** |

**Authentication and key binding are two different things**, and conflating
them is the standard mistake. Identity-bound encryption needs both:

1. **Authenticate as the user** — build an `OidcFederationStrategy` (or
   `AccessKeyStrategy` for service-to-service) and pass it as
   `config.authStrategy`. The client then acts as that user for its lifetime.
   **Available on this entry**, and shown below.
2. **Bind the data key to a claim** — chain `.withLockContext({ identityClaim })`
   on the operation. *This* is what binds key retrieval to the user's claim.
   **Not available on this entry**
   ([#797](https://github.com/cipherstash/stack/issues/797)).

> [!IMPORTANT]
> **An auth strategy alone does not produce identity-bound data.** It decides
> *who the client is*; a lock context decides *who can retrieve a value's
> data key* (the claim from the encrypting caller's service token is bound to
> the key — `stash-auth` is canonical). Only the first exists here, so on
> this entry today:
>
> - Values you write carry **no identity condition on key retrieval** — any
>   client with keyset access can decrypt them — even with a per-user
>   `authStrategy`.
> - You **cannot read** anything the native entry wrote under a lock context,
>   because key retrieval requires the same claim. That is a silent split in
>   what the two entries can read, on top of the schema incompatibility below.
>
> If a value must be bound to an end-user claim, encrypt and decrypt it on the
> native entry. Don't reach for `as any` to force a lock context through here —
> there is nothing on the other side to receive it.

The strategy replaced the old per-operation token ceremony
(`LockContext.identify()`, deprecated) — it did **not** replace the lock
context, and the native entry still chains `.withLockContext()` for that.

```ts
import { Encryption, OidcFederationStrategy } from '@cipherstash/stack/wasm-inline'

// `create` returns a Result — unwrap it. Passing the Result itself as
// `authStrategy` is the easy mistake, and it fails opaquely later.
const strategy = OidcFederationStrategy.create(
  workspaceCrn,                   // 'crn:<region>:<workspace-id>'
  () => getUserJwt(req),          // called on every re-federation — Clerk, Supabase Auth, …
)
if (strategy.failure) throw new Error(strategy.failure.error.message)

const client = await Encryption({
  schemas: [users],
  config: { authStrategy: strategy.data, clientId, clientKey },
})

// Authenticated as the end user — but the value carries no identity condition
// on key retrieval. There is no `.withLockContext()` on this entry to bind it.
const enc = await client.encrypt('alice@example.com', {
  table: users,
  column: users.email,
})
if (enc.failure) throw new Error(enc.failure.message)
```

**On the native entry, where lock contexts do exist, the same claim must be
supplied on decrypt.** A value encrypted under a lock context and decrypted
without one — or under a different claim — does not come back. This is the
single most common identity-aware encryption bug, and it does not surface as a
key error; it surfaces as a failed decrypt. It is also why an edge function
cannot read what a lock-context-using Node service wrote.

`AccessKeyStrategy.create(workspaceCrn, accessKey)` has the same
Result-returning shape, for service-to-service use with a custom token store.
When you pass an auth strategy, do **not** also pass `config.accessKey` — they
are mutually exclusive and the client rejects the combination.

Construct a client **per request** when using a user-scoped strategy — a
module-level client would bind whichever user happened to arrive first.

### The bulk shape differs — don't copy the native form

```ts
// WASM entry: each entry carries its own table and column.
const out = await client.bulkEncrypt([
  { plaintext: 'a@example.com', table: users, column: users.email },
  { plaintext: 'b@example.com', table: users, column: users.email },
])
if (out.failure) throw new Error(out.failure.message)
// out.data is index-aligned; a null/undefined plaintext yields null at that index.
```

The model helpers (`encryptModel` / `decryptModel` and their bulk forms) *are*
present on this entry, and the traversal is the same one the native entry runs
— declared columns encrypted by JS property name, everything else passing
through, one ZeroKMS round trip per call.

**The decrypt side has no table-less form.** Both entries take the table as the
second argument, and on both that is the form to prefer. What the native client
*also* offers is a one-arg `decryptModel(model)` overload — the read path for
rows whose table isn't in the schema set, legacy EQL v2 above all, at the cost
of `Date` reconstruction and a precise plaintext shape. This entry has no such
overload: `decryptModel(model, table)` and `bulkDecryptModels(models, table)`
**require** the table, because they resolve date fields from a per-table map
built at client construction. Omitting it throws rather than returning a
`{ failure }`, and a table the client was not initialized with is a defined
failure:

```ts
const rows = await client.bulkDecryptModels(encryptedRows, users)
if (rows.failure) throw new Error(rows.failure.message)
```

A wrapper written against the native signature will therefore compile against
one entry and break on the other. This is a *client*-surface difference — the
schema module itself is shareable (see below); wrapper code is not.

## Schema Modules Cross Entries

**One schema module serves both entries.** A table authored with
`encryptedTable`/`types` from `@cipherstash/stack/v3` builds the WASM entry's
`Encryption`, and one authored from `@cipherstash/stack/wasm-inline` builds the
native `Encryption` — same types, same runtime, both directions:

```ts
// schema.ts — the single source of truth for this project's schema
import { encryptedTable, types } from '@cipherstash/stack/wasm-inline'

export const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  ssn:   types.TextEq('ssn'),
})
```

Author it against whichever entry the schema module's own runtime needs — the
wasm-inline entry if that module is itself imported by the Edge Function — and
pass the result to either client.

> **On older `@cipherstash/stack` versions this did not typecheck.** The two
> entries shipped separately-emitted declarations of the column classes, and
> those classes carry `private` fields, which TypeScript compares **nominally** —
> so each entry rejected the other's schema in both directions:
>
> ```text
> Type 'EncryptedTextSearchColumn' is not assignable to type 'AnyEncryptedV3Column'.
>   Types have separate declarations of a private property 'columnName'.
> ```
>
> The runtime was never affected, which was the trap: `as never` / `as any` on
> the schema looked like the fix while silencing a signal that would matter after
> a genuine schema mismatch. If you see this diagnostic, upgrade rather than
> assert — or, on a version you cannot move off, author the schema module against
> exactly one entry and build only that entry's client from it.

What still does **not** cross is the *client* surface: the two entries' clients
differ in the ways listed above (the `bulkDecryptModels` signature, config
shape). A helper written against one client's signatures will not compile against
the other, so keep wrapper code entry-specific even though the schema is shared.

### `@cipherstash/stack-supabase/wasm-inline`

The Supabase adapter's edge entry runs the WASM engine but types its `schemas`
option from `@cipherstash/stack/eql/v3`. That used to make it a special case —
authoring the schema from `@cipherstash/stack/wasm-inline` was rejected there,
reported one level up as `schemas` not assignable to `AnyV3Table`. It is no
longer: every entry now resolves one declaration of the column classes, so
either import works and both examples below are correct.

```ts
// The engine is WASM either way. The schema's declaration site no longer matters.
import { encryptedSupabase } from '@cipherstash/stack-supabase/wasm-inline'
import { encryptedTable, types } from '@cipherstash/stack/eql/v3'
// …or from '@cipherstash/stack/wasm-inline' — same classes, same result.
```

On a version predating that fix the old rule still applies: author from
`eql/v3` for this adapter. `stash-supabase` and `stash-managed-platforms`
carry the full edge call shape.

## Querying from the Edge

Edge functions rarely have an ORM, so encrypted search is usually hand-written
SQL over `pg` or `postgres-js`. Mint the search needle with `encryptQuery`,
then bind it as a typed parameter:

```ts
const term = await client.encryptQuery('alice@example.com', {
  table: users, column: users.email, queryType: 'equality',
})
if (term.failure) throw new Error(term.failure.message)

// postgres-js — bind the unwrapped term, not the Result
const rows = await sql`
  SELECT * FROM users
   WHERE email = ${sql.json(term.data)}::jsonb::eql_v3.query_text_eq`
```

The predicate forms, the per-driver binding rules, and the query-domain names
are the subject of `stash-postgres` — read it before writing the first query. The
two rules that bite immediately: the operand must be **cast to the column's
`eql_v3.query_*` domain**, and on `postgres-js` payloads must be bound with
`sql.json(...)`, never pre-stringified.

## Troubleshooting

**`Dynamic require of "..." is not supported` / a native `.node` file in the bundle**
— the native entry got imported. Check every import path resolves to
`@cipherstash/stack/wasm-inline`, including transitive ones from your own
shared modules.

**`require(...) is not a function` / the specifier won't resolve in CJS** — this
entry is ESM-only. Move the consumer to ESM.

**Missing `CS_*` at runtime** — the secret store was never populated, or the
function was served without `--env-file`. Validate the ones you pass at handler entry
and return an actionable error rather than letting client construction fail
opaquely; the example in `examples/supabase-worker` does exactly this.

**Encryption works, search returns zero rows** — not a credential problem: a
keyset mismatch fails everything loudly, decrypt included (see [Keysets and
Credentials](#keysets-and-credentials-when-search-returns-zero-rows) and
`stash-zerokms`). Empty results with working decrypt point at an untyped
operand or wrong predicate form (`stash-postgres`); a missing index (see
`stash-indexing`) makes queries slow, not empty.

**Search needle rejected** — free-text needles must be at least 3 characters;
shorter ones tokenize to nothing.

**Cold-start latency** — the inlined WASM module is compiled on first use.
Construct the client at module scope when the auth strategy is not
user-scoped, so it is reused across invocations on a warm isolate.

## Reference

- `stash-zerokms` — keysets, clients, grants, and the key hierarchy (canonical).
- `stash-auth` — credentials, auth strategies, and lock context (canonical).
- `stash-postgres` — the raw-SQL predicate cookbook and driver binding rules.
- `stash-encryption` — schema authoring, the `types.*` domain catalog, and the
  rollout/cutover lifecycle.
- `stash-cli` — `stash env`, `stash eql install`, `stash encrypt backfill`.
- `stash-indexing` — indexes on encrypted columns (the DDL is the same
  wherever the app runs).
- `stash-supabase` — the PostgREST wrapper, for Supabase apps that are not
  writing raw SQL.
- Working example: `examples/supabase-worker` in the `cipherstash/stack` repo.
- Bundling guide: https://cipherstash.com/docs/stack/deploy/bundling
