---
name: stash-edge
description: Run CipherStash encryption on edge and non-Node runtimes with the `@cipherstash/stack/wasm-inline` entry — Deno, Supabase Edge Functions, Cloudflare Workers, and Bun. Covers the import specifier per runtime, the four mandatory `CS_*` variables and minting them with `stash env`, the credential-identity rule (rows written under different credentials decrypt but never match a query), how the WASM client surface differs from the native typed client, and why an EQL v3 schema module cannot be shared across the two entries. Use when adding encryption to a Supabase Edge Function, a Worker, or a Deno service; when a native module fails to load in a deployed runtime; when wiring `CS_*` secrets into an edge deploy; or when encrypted search returns zero rows on the edge but works locally.
---

# Encryption on the Edge (WASM entry)

`@cipherstash/stack` has two runtime entries. The default one binds
`@cipherstash/protect-ffi`, a Node-API native module, and must be loaded by
Node's own `require`. **`@cipherstash/stack/wasm-inline` is the entry for
everywhere else** — it carries the WASM build of the same engine as a base64
blob inside the JS, so there is no native binding, no separate `.wasm` fetch,
and nothing for a bundler to externalise.

This skill covers that entry and the deployment shape around it. It is EQL v3
throughout. For the SQL that actually queries the encrypted columns — the
predicate forms and driver binding rules — see `stash-sql`; edge functions
almost always talk to Postgres over a raw driver, so the two are usually read
together.

## When to Use This Skill

- Adding encryption to a Supabase Edge Function, Cloudflare Worker, Deno
  service, or Bun app.
- A deployed runtime fails to load the native module (`protect-ffi`), or a
  bundler chokes trying to include it.
- Wiring `CS_*` credentials into an edge deploy, or minting them at all.
- Encrypted search works locally but returns **zero rows** in the deployed
  function — see [The Credential-Identity Rule](#the-credential-identity-rule-a-silent-data-footgun).
- A schema module shared with Node tooling fails to typecheck against the
  edge client.

## Choosing the Entry

| Runtime | Entry | Why |
|---|---|---|
| Node server, Next.js server code | `@cipherstash/stack` (+ `/v3`) | Native NAPI is faster; keep `@cipherstash/protect-ffi` external (e.g. Next's `serverExternalPackages`) |
| Supabase Edge Functions | `@cipherstash/stack/wasm-inline` | Deno, V8-only, no native modules |
| Cloudflare Workers | `@cipherstash/stack/wasm-inline` | V8 isolate, no native modules |
| Deno (any) | `@cipherstash/stack/wasm-inline` | No NAPI under Deno's default permissions |
| Bun | `@cipherstash/stack/wasm-inline` | Works, and avoids native-module resolution differences |
| Anywhere bundling server code | `@cipherstash/stack/wasm-inline` | Bundles cleanly; nothing to externalise |

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
} from 'npm:@cipherstash/stack@1.0.0-rc.4/wasm-inline'
```

**Pin an exact version.** Deno caches by specifier, so an unpinned import
drifts between deploys. And while the package is on a prerelease line, a
caret range does not do what it looks like: `@^1.0.0` will **not** match
`1.0.0-rc.4`, because semver ranges exclude prereleases unless the range
itself names one. Use the exact version, or a prerelease-bearing range
(`@^1.0.0-rc.4`). Check what is current with `npm view @cipherstash/stack dist-tags`.

### Deno with an import map

For a project with a `deno.json`, map the specifier once and import the bare
name everywhere:

```jsonc
{
  "imports": {
    "@cipherstash/stack/wasm-inline": "npm:@cipherstash/stack@1.0.0-rc.4/wasm-inline"
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
build config already externalises `@cipherstash/protect-ffi` for the native
entry, that config does not apply here and can be left alone.

## Credentials

The edge client takes **all four** `CS_*` values explicitly. There is no
credential discovery: `~/.cipherstash` does not exist in a Worker or an Edge
Function container, and there is no device-code login to fall back on.

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

## The Credential-Identity Rule (a silent data footgun)

> **Every writer of a searchable column must use the same credentials as every
> reader — including `stash encrypt backfill`, seed scripts, and admin tools.
> Rows written under different credentials decrypt correctly but never match a
> query.**

EQL's searchable-encryption index terms (the `hm`, `op`, `bf` fields in the
stored payload) derive from the **ZeroKMS client key**, not from the workspace
or keyset. Two clients in the same workspace with different `CS_CLIENT_ID` /
`CS_CLIENT_KEY` pairs therefore produce **different terms for the same
plaintext**.

The consequences are asymmetric, which is what makes this hard to spot:

- **Decryption still works.** The data key is wrapped through ZeroKMS against
  the workspace, so any authorised client in the workspace can decrypt the
  row. Round-trip tests pass.
- **Search silently fails.** An equality or match predicate compares the
  query term against the stored term. Different client keys, different terms,
  no match — and no error. The query returns zero rows exactly as though the
  data were absent.

The classic way to hit it: run `stash encrypt backfill` from a laptop (using
the local device-profile credentials), then query those rows from an Edge
Function using `CS_*` values minted by `stash env`. Every row decrypts. No
search ever matches.

**What to do:**

- Mint one credential per *environment*, and use it for **every** process that
  touches that environment's data — the app, the backfill, seed scripts, admin
  jobs, and one-off scripts alike.
- Before running `stash encrypt backfill` against an environment, export that
  environment's `CS_*` values into the shell running it.
- If rows have already been written under the wrong credentials, re-encrypt
  them with the correct client: read (decryption still works), then write back
  through a client built with the target credentials.

**Diagnosing it:** if `decrypt` returns the right plaintext but an equality
query on the same row returns nothing, compare the stored term against a
freshly minted one for the same plaintext. Matching plaintext with differing
`hm` values is this bug, not an indexing problem.

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
| Schema authoring | `encryptedTable` / `types` from `@cipherstash/stack/v3` | the entry's own re-exports (see below) |
| Config | discovered from env / `~/.cipherstash` | all four `CS_*` passed explicitly |
| Typing | signatures derived from the schema | schema-aware, but not the full typed client |
| `.audit()` | chainable on operations | **not available** |
| `.withLockContext()` | chainable on operations | **not available** — see below |
| `bulkEncrypt` shape | `(plaintexts, { table, column })`, `{ id, plaintext }` envelopes | per-item `{ plaintext, table, column }`, plain index-aligned array |
| Module format | ESM + CJS | **ESM only** |

**Identity-bound encryption is configured, not chained.** There is no
`.withLockContext()` on this entry. Build an `OidcFederationStrategy` (or
`AccessKeyStrategy` for service-to-service) and pass it as
`config.authStrategy`, so the client is authenticated *as the end user* for
its whole lifetime:

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
```

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
present on this entry and behave as they do natively — declared columns
encrypted by JS property name, everything else passing through, one ZeroKMS
round trip per call.

## Schema Modules Do Not Cross Entries

A schema authored with `@cipherstash/stack/v3` **will not typecheck**
against the WASM entry's `Encryption`, and the reverse fails too:

```
Type 'EncryptedTextSearchColumn' is not assignable to type 'AnyEncryptedV3Column'.
  Types have separate declarations of a private property 'columnName'.
```

The two entries ship independent type bundles, and the column classes carry
private fields — which TypeScript compares **nominally**. The declarations are
identical in shape but not the same declaration, so assignment is rejected in
both directions.

It works fine at runtime, which is the trap: the tempting fix is
`as never` / `as any` on the schema, which silences a real signal and will
keep silencing it after a genuine schema mismatch appears.

**Author the schema module against exactly one entry, and use that entry's
client with it.** For a project whose encryption runs on the edge, that means
importing `encryptedTable` and `types` from `@cipherstash/stack/wasm-inline`
in the shared schema module:

```ts
// schema.ts — the single source of truth for this project's schema
import { encryptedTable, types } from '@cipherstash/stack/wasm-inline'

export const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  ssn:   types.TextEq('ssn'),
})
```

Node-side code that imports this module must then also build its client from
`@cipherstash/stack/wasm-inline` (which runs on Node perfectly well, just with
the WASM engine rather than the native one) and must be ESM.

If a project genuinely needs the native client on the server *and* the WASM
client on the edge, keep two schema modules and treat their agreement as
something to test, not something the type system will enforce for you. Column
names and domains must match exactly — they are what the database and the
stored payload's `i` identifier are keyed by.

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
are the subject of `stash-sql` — read it before writing the first query. The
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
function was served without `--env-file`. Validate all four at handler entry
and return an actionable error rather than letting client construction fail
opaquely; the example in `examples/supabase-worker` does exactly this.

**Encryption works, search returns zero rows** — the credential-identity rule
above. Second most likely: a missing index (see `stash-indexing`) makes it
slow, not empty, so empty results point at credentials or an untyped operand
(`stash-sql`).

**Search needle rejected** — free-text needles must be at least 3 characters;
shorter ones tokenize to nothing.

**Cold-start latency** — the inlined WASM module is compiled on first use.
Construct the client at module scope when the auth strategy is not
user-scoped, so it is reused across invocations on a warm isolate.

## Reference

- `stash-sql` — the raw-SQL predicate cookbook and driver binding rules.
- `stash-encryption` — schema authoring, the `types.*` domain catalog, and the
  rollout/cutover lifecycle.
- `stash-cli` — `stash env`, `stash eql install`, `stash encrypt backfill`.
- `stash-indexing` — indexes on encrypted columns (the DDL is the same
  wherever the app runs).
- `stash-supabase` — the PostgREST wrapper, for Supabase apps that are not
  writing raw SQL.
- Working example: `examples/supabase-worker` in the `cipherstash/stack` repo.
- Bundling guide: https://cipherstash.com/docs/stack/deploy/bundling
