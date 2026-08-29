---
name: stash-managed-platforms
description: >-
  Implement CipherStash encryption on a managed AI app platform — Lovable, v0,
  Bolt, Replit, and anything else with no developer-controlled shell, an
  edge/Workers runtime, a database role that is not `postgres`, and schema
  changes only through the platform's own migration tool. Covers the one fact
  that decides whether the product works there at all (use `@cipherstash/stack`
  with the `wasm-inline` entry — `@cipherstash/protect` is the deprecated
  predecessor and its native module will not load), running `stash auth login
  --json` headlessly in an ephemeral sandbox, minting deployment credentials
  with `stash env`, installing EQL as a role that is not `postgres`, which query
  predicates survive PostgREST, and how to construct `encryptedSupabase` inside
  a Worker by declaring your schemas. Also covers the platform guards that break
  installs: command-time ceilings that kill the EQL bundle partway
  (half-installed schema after a 600s limit), the PostgREST grants the installer
  never emits, minimum-release-age cooldowns refusing a fresh release ("version
  too new"), and secrets handoff when there is no secrets API. Use when the
  project is hosted on one of these platforms, when there is no terminal you
  control, when a native module fails to load in the deployed runtime, when an
  EQL install times out or PostgREST calls fail with permission errors, when a
  freshly published package refuses to install, or when you are about to
  conclude CipherStash cannot be used here.
---

# CipherStash on Managed AI App Platforms

## Read this first: it does work here

If you are on Lovable, v0, Bolt, Replit, or a similar hosted builder, and you have found `@cipherstash/protect` and inferred from its `@cipherstash/protect-ffi` dependency that CipherStash needs a native Rust addon and therefore cannot run on an edge runtime — **that inference is about the wrong package.**

- **`@cipherstash/stack` is the current package.** Import the `@cipherstash/stack/wasm-inline` entry. It carries the WASM build of the same engine as a base64 blob inside the JS: no native binding, no separate `.wasm` fetch, nothing for a bundler to externalise, no `--allow-ffi`.
- **`@cipherstash/protect` is the deprecated predecessor.** Its native FFI will not load in a Worker or an Edge Function. Do not install it, and do not use it to decide what the product can do.

An agent working on one of these platforms previously spent a full turn concluding CipherStash was impossible in a Lovable project before finding `stash` and the WASM entry. Nothing about that conclusion was true. Everything below is the rest of what that turn had to discover.

The `stash-edge` skill is the full guide to the WASM entry (per-runtime import specifiers, the client surface, why schema modules cannot be shared across entries). This page covers what is specific to *managed* platforms.

## When to Use This Skill

Use it when the environment has any of these four properties — they travel together and each one changes the setup:

1. **No shell the developer controls.** Commands run in an ephemeral sandbox, or not at all.
2. **An edge / Workers runtime** for server code.
3. **A database role that is not `postgres`** and is not a member of it (Lovable's is `sandbox_exec`).
4. **Database changes only through the platform's migration tool**, not a psql session.

Do not use it for a normal Node deployment on a VM or a container — that is `stash-deployment`.

## The CLI authenticates headlessly. Use it.

The most common wrong turn after the WASM one is assuming the CLI cannot log in without a browser on the machine, and reaching for a raw EQL `.sql` release asset instead. The device flow is designed for exactly this case.

```bash
stash auth login --json --region us-east-1
```

`--json` emits newline-delimited JSON on stdout, one object per line, and deliberately does **not** open a browser — the human opens the URL, not the agent's host. The first event, `authorization_required`, carries `verificationUri` / `verificationUriComplete` and a `userCode`; print it and ask the person to approve it. Credentials are written to `~/.cipherstash`, which exists fine inside a sandbox.

Three things to get right:

- **`--region` is required in a non-TTY.** Without it (or `STASH_REGION`) the region picker cannot render and the command exits `region_required`. `stash auth regions --json` lists the valid slugs.
- **After printing `authorization_required` the command blocks**, polling until approval or expiry (~900 s). Run it as a background task with a generous timeout — do not treat the pause as a hang.
- **Authenticate before `stash init`.** An unauthenticated `init` tries to start a login of its own.

Then drive everything else through the CLI: `stash manifest --json` is the authoritative command surface, and `--json` modes exist on the commands an agent needs. Never `cat` anything under `~/.cipherstash` — the CLI reads it for you, and its contents are secrets.

## Deployment credentials: `stash env`

The four `CS_*` variables a deployed app needs are minted in one command:

```bash
stash env --name my-app-prod --write .env.production.local
```

`--name` is **required** in a non-interactive run. Without `--write` the dotenv block goes to stdout and progress UI goes to stderr, so redirecting into a file or piping into a secret store is safe. With `--write` the file is mode 0600, and an existing file is *refused* non-interactively rather than silently overwritten. The access key is shown exactly once.

Put those four values into the platform's backend-secrets UI. That is the whole story on these platforms and it works as-is — `stash-auth` is canonical for what each variable is and how the strategies use them.

## The database role is not `postgres`, and that is fine

`stash eql install` completes as a non-`postgres` role. Only three owner-scoped `ALTER DEFAULT PRIVILEGES FOR ROLE postgres` statements are skipped, and they are **optional**: they cover EQL objects `postgres` might later create outside stash tooling, and stash re-grants every object on each install and upgrade. The CLI prints the skipped statements under "Optional SQL — requires postgres" for an operator who wants to apply them another way.

**Check before you install**, and pass the report to the human rather than guessing:

```bash
stash eql preflight --json
```

It reports `current_user`, superuser, membership of `postgres` (never blocking), `CREATE` on the database and on `public`, `pgcrypto` presence *and placement*, whether the role can create an operator class, and whether the EQL schemas already exist. Each blocked row names the statement it blocks. Exit 1 means a genuine blocker.

Two of its answers change what you write afterwards:

- **`ORE operator class: not creatable`** — declare ordered columns `types.*Ord`, never `types.*OrdOre`. See the capability matrix in `stash-encryption`; the short version is that the ORE domains get an always-raising CHECK on such a database, so writes to them fail.
- **`pgcrypto` outside `extensions` / `public`** aborts the bundle for *any* role, superuser included.

### Getting the SQL applied through the platform's migration tool

Where you cannot hold a connection open — or where the platform replays a migrations directory and would wipe a direct install — generate a migration instead of installing:

```bash
stash eql migration --supabase     # writes into supabase/migrations/
stash eql migration --drizzle      # a Drizzle custom migration
```

On a Supabase-backed platform this is the **only durable** option: `supabase db reset` replays `supabase/migrations/` and discards anything a direct `eql install` did. The generated Supabase migration wraps the owner-scoped statements in a `pg_has_role` guard, so it applies cleanly whatever role the platform's migration runner uses — a non-member role skips them instead of aborting the whole migration.

Then commit the migration through the platform's Git sync and let its own migrate step apply it.

### When the platform caps command time

Some platforms kill any command after a fixed ceiling (Lovable: 600 seconds). The EQL v3 bundle
is ~2.6 MB / ~6,300 SQL statements, and `psql -f` sends **one statement per protocol round trip** —
over a pooled connection that is tens of milliseconds each, which blows past the ceiling and kills
the install **partway**, leaving schemas and domains created but functions and operators missing.
Retrying the same command hits the same wall.

- Prefer `stash eql install` or the generated migration over replaying the raw bundle with
  `psql -f`.
- If you must apply raw SQL under a ceiling, split the bundle at top-level statement boundaries
  (dollar-quote aware) into chunks of well under 128 KB and apply **each chunk as a single
  command** (`psql -c "<chunk>"`) — one round trip per chunk instead of per statement. ~27 chunks
  applies in seconds.
- Cleaning up a half-install may fail with ownership errors: the broken objects are owned by the
  platform's app role, not `postgres`. Grant the app role to the cleaning role (e.g.
  `GRANT sandbox_exec TO postgres` on Lovable) before dropping and re-applying.

### Grant the Data API roles after installing

The EQL install grants nothing to Supabase's PostgREST roles. Every function-form call from the
Data API — including a `SECURITY INVOKER` RPC that wraps EQL predicates — fails with a permission
error until you run, as part of the same migration:

```sql
GRANT USAGE ON SCHEMA eql_v3 TO authenticated, anon, service_role;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA eql_v3 TO authenticated, anon, service_role;
```

`GRANT ... ON ALL FUNCTIONS` covers only the functions that exist when it runs — a later
`stash eql upgrade` that adds functions is not covered. Re-run the grants after every upgrade, or
make them durable up front with
`ALTER DEFAULT PRIVILEGES IN SCHEMA eql_v3 GRANT EXECUTE ON FUNCTIONS TO authenticated, anon, service_role;`
(run as the role that performs the installs).

## Fresh releases are blocked by install cooldowns

Managed platforms and modern runtimes ship supply-chain guards that refuse packages published
within the last ~24 hours: Lovable sets `minimumReleaseAge` in `bunfig.toml`, Deno ≥ 2.9 has
`--minimum-dependency-age`. Installing a CipherStash release on its publish day fails with a
"version too new" style refusal, not a helpful message. Add the packages to the platform's exclude
list (`minimumReleaseAgeExcludes` in `bunfig.toml`: `@cipherstash/stack`, `@cipherstash/eql`,
`@cipherstash/protect-ffi`) — and say in your report that you relaxed a supply-chain guard to do
it. If you can wait a day, wait instead.

## What survives PostgREST

If the app talks to the database through Supabase's Data API rather than a Postgres connection, the predicate surface is narrower than the type surface. Agents guess wrong in **both** directions on this, so take it from the table:

| Through PostgREST | Works? |
|---|---|
| `eq`, `neq`, `in`, `match()` | ✅ — the adapter encrypts each filter value with the full storage path |
| `gt`, `gte`, `lt`, `lte` | ✅ on range-capable domains (`*_ord`, `text_search`) |
| `order()` | ✅ on OPE-backed ordering columns only (`*_ord`, `text_ord`, `text_search`) |
| `matches()` — encrypted free-text | ❌ needs `@@` with an `eql_v3.query_*` cast PostgREST cannot emit |
| encrypted `contains()` / `selectorEq()` / `selectorNe()` | ❌ needs an `eql_v3.query_json` cast, likewise |

The wrapper fails fast on the unsupported ones rather than silently returning wrong rows. Do not reach for `like` / `ilike` / raw `cs` as substitutes — they are not equivalent and will not match encrypted data.

When you need free-text or encrypted-JSON predicates, the query has to go through something that can emit a cast: Drizzle, Prisma Next, or hand-written SQL in an RPC (`stash-postgres` has the raw forms). `stash-supabase` is canonical for the adapter's full behaviour, including the security note about filter operands travelling in GET query strings.

## `encryptedSupabase` in a Worker: declare your schemas

The rule: **declare your schemas and it runs anywhere; omit them and we discover them for you, which needs a database connection and is therefore Node-only.**

By default `encryptedSupabase` derives every column's encryption config by introspecting the database, which needs a **Postgres connection** — unavailable in a Worker or an Edge Function. Passing `schemas` skips introspection entirely, so there is nothing left to connect to:

```typescript
import { encryptedSupabase } from '@cipherstash/stack-supabase/wasm-inline'
import { encryptedTable, types } from '@cipherstash/stack/wasm-inline'

const users = encryptedTable('users', {
  email: types.TextSearch('email'),
  age: types.IntegerOrd('age'),
})

const supabase = await encryptedSupabase(supabaseClient, {
  schemas: { users },          // no databaseUrl — nothing introspects
  config: { workspaceCrn, accessKey, clientId, clientKey },
})
```

**Two things must both be right**, and each fails independently:

1. **The entry.** Import from `@cipherstash/stack-supabase/wasm-inline`, not the package root. The root statically imports the native engine, which loads on import whether or not you encrypt anything.
2. **The schemas.** Without them the wrapper still wants a connection.

What declared mode gives up, it gives up loudly rather than silently:

- **`select('*')` and bare `select()` are refused.** Nothing enumerated the table's plaintext columns, and an unexpanded `*` reaches PostgREST without the `::jsonb` casts encrypted columns need. List columns explicitly.
- **`from()` on an undeclared table throws.** There is no introspected table list to fall back on.
- **The drift check is gone** — nothing compared your declaration against the real column domains, so a wrong domain surfaces as a `23514` CHECK violation on the first write instead of at construction. On Node you can have both: pass `databaseUrl` **as well as** `schemas`.

⚠️ **The one tradeoff that is not loud — declare every encrypted column of every table you query.** Nothing introspects, so a column carrying an `eql_v3` domain in the database but missing from your `schemas` is treated as an ordinary plaintext column: a `select` naming it hands you the raw EQL payload as data, and a filter on it sends your **plaintext** value to PostgREST. There is no error, because nothing knows the column is encrypted. If you cannot guarantee the declaration is complete, pass `databaseUrl` so introspection fills the gaps.

An ambient `DATABASE_URL` will not overrule your declaration — it is ignored when `schemas` are passed, with a warning that the declaration is unverified. Pass `databaseUrl` explicitly if you want introspection.

Passing `databaseUrl` to the `wasm-inline` entry is refused outright — it carries no Postgres driver, and saying so beats ignoring the option.

Prefer to keep encryption out of the adapter entirely? Use `@cipherstash/stack/wasm-inline` directly: encrypt and decrypt with the client and send EQL payloads through the Supabase JS client or raw SQL yourself. `stash-edge` covers the client surface, `stash-postgres` the SQL forms.

## Order of operations

1. `stash auth login --json --region <slug>` — hand the verification URL to the human.
2. `stash eql preflight --json` — report the role's capability before changing anything.
3. `stash eql migration --supabase` (or `--drizzle`), committed through the platform's Git sync — not a direct `eql install`, if the platform replays a migrations directory.
4. `stash init`, then `stash plan` / `stash impl --target <target>` to scaffold and hand off. On Lovable, `--target lovable` writes an `AGENTS.md` whose next-steps are platform-specific.
5. `stash env --name <env> --write` — put the four `CS_*` values into the platform's backend
   secrets. **On Lovable, who sets them depends on where you are running:** the in-product agent
   can set project secrets itself, so mint with `stash env` and store them directly. Driving
   Lovable from outside — over the Lovable MCP server, which has no secrets tool — there is no
   programmatic path, so hand off through one of two routes: the human runs `stash env` themselves
   and pastes the values into Project Settings → Secrets, or you write them to the 0600 file with
   `--write` and the human copies from that file, then deletes it. Never paste the values into
   chat or logs — the sanctioned surfaces are the platform's secret store and that transient
   0600 file.
6. Write the schema with `types.*Ord`, not `*OrdOre`, unless preflight said the operator class is creatable.
7. `stash eql verify` — confirm the installed surface is complete before shipping.

## Related skills

- `stash-edge` — the WASM entry in depth: per-runtime imports, the client surface, credentials on the edge.
- `stash-supabase` — the `encryptedSupabase` wrapper, its filters, and the full PostgREST behaviour.
- `stash-cli` — every command, its flags, and the non-interactive escape hatches.
- `stash-auth` — canonical for `CS_*`, auth strategies, and lock context.
- `stash-encryption` — the capability matrix: which `types.*` factory supports which predicate.
- `stash-postgres` — raw SQL with the `eql_v3.query_*` operand casts, for the no-ORM fallback.
