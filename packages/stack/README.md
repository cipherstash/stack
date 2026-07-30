<!-- Before merging to main, work through docs/plans/readme-go-live-checklist.md — it tracks the
     remaining pre-merge items (doc links, benchmark refresh, social preview card). -->
<div align="center">
  <a href="https://cipherstash.com?utm_source=github&utm_medium=stack_readme">
    <img alt="CipherStash" width="128" height="128" src="https://cipherstash.com/brand/cipherstash-logo-dark.svg">
  </a>
  <h1>CipherStash Stack for TypeScript</h1>

  <p><b>Searchable, application-level encryption for building privacy-first apps.</b></p>

  <a href="https://www.npmjs.com/package/@cipherstash/stack"><img alt="npm version" src="https://img.shields.io/npm/v/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://www.npmjs.com/package/@cipherstash/stack"><img alt="npm downloads" src="https://img.shields.io/npm/dm/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/cipherstash/stack?style=for-the-badge&labelColor=000000"></a>
  <a href="https://cipherstash.com/docs/stack?utm_source=github&utm_medium=stack_readme"><img alt="Docs" src="https://img.shields.io/badge/Docs-333333.svg?style=for-the-badge&logo=readthedocs&labelColor=333"></a>
  <a href="https://discord.gg/5qwXUFb6PB"><img alt="Discord" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Discord&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>

  <div>⭐ Star this repo if encryption you can actually query is your thing!</div>
</div>


## Encryption-level security without the pain

Field-level encryption is the strongest way to protect data.
But if DB functionality or performance suffers, you need to justify the pain.
Searchable Encryption nukes the trade-off: encryption-level security without the pain.

* Searchable Encryption for any Postgres including Supabase, RDS, Aurora, Prisma Postgres and Neon
* Works with Supabase.js, Prisma Next, Drizzle or plain SQL
* Built-in key management — automatic rotation, auditing and up to 14x faster than AWS KMS
* Integrates with Supabase Auth, Clerk, Auth0 and Okta

<br/>

## Quick starts

### Use the wizard

Takes 5-10 minutes, starts on the **free developer tier** ([sign up][signup]), includes agent handoff.

```bash
# Run this to start (or just ask Claude to)
npx stash init
```

### ORM/database-specific guides

| Quick start | Guide |
|---|---|
| **Supabase** | [Supabase quickstart →][supabase] |
| **Prisma Next** | [Prisma Next quickstart →][prisma-next] |
| **Drizzle ORM** | [Drizzle quickstart →][drizzle] |
| **Raw PostgreSQL (`pg`)** | [PostgreSQL quickstart →][encryption] |
| **DynamoDB** | [DynamoDB quickstart →][dynamodb] |

> The Stack also ships a `stash` CLI for auth, schema, and database setup. See the [SDK reference][reference].

## What's in the Stack

### 🔐 Searchable encryption

Encrypt individual fields and still run real queries against them — all on ciphertext, in PostgreSQL:

| Query type | Operations | Docs |
|---|---|---|
| **Equality** | `=`, `IN` | [Equality queries →][query-equality] |
| **Free-text search** | fuzzy `matches` | [Text search →][query-match] |
| **Range & ordering** | `<`, `>`, `BETWEEN`, `ORDER BY`, `MIN`/`MAX` | [Range queries →][query-range] |
| **Encrypted JSON** | containment (`@>`), JSONPath selectors | [JSON queries →][query-json] |

With [EQL v3][eql], the column type *is* the configuration. Declare a column with the encrypted type
that names its data type and the operations it supports, and it's ready to query — there's no per-column
search configuration to maintain in your client:

```sql
CREATE TABLE users (
  id          serial PRIMARY KEY,
  username    text,                    -- plaintext — business as usual
  email       eql_v3_text_match,       -- encrypted · free-text search
  ssn         eql_v3_text_eq,          -- encrypted · equality
  salary      eql_v3_integer_ord,      -- encrypted · range + ORDER BY
  preferences eql_v3_json_search       -- encrypted · containment + selectors
);
```

Encrypted types exist for text, integers, floats, numerics, dates, timestamps, booleans, and JSON, so
your schema documents itself — and encrypted data stays indexable with standard Postgres indexes. No
special index engine, no SQL rewrites. ORMs pick the types up transparently: declare the column as
encrypted in `schema.prisma` or your Drizzle table and the Stack handles the rest. Only raw `pg` needs
a client-side [schema][schema] — declared with the same type names:

```typescript
import { encryptedTable, types } from "@cipherstash/stack/v3";

const users = encryptedTable("users", {
  email: types.TextMatch("email"),       // ↔ eql_v3_text_match
  salary: types.IntegerOrd("salary"),    // ↔ eql_v3_integer_ord
});
```

→ [Searchable encryption][searchable-encryption] · [Schema][schema] · [Encrypt & decrypt][encrypt-decrypt] · [Bulk & model operations][model-ops]

### 🔑 Authentication

How you authenticate to ZeroKMS depends on who's asking for keys:

- **Device auth** — browser-based login for local development: `npx stash auth login` opens your
  browser and saves credentials to your local CipherStash profile. No secrets in your repo or shell.
- **Access key auth** — service-level credentials for servers, workers, and CI, supplied via `CS_*`
  environment variables.
- **OIDC federation** — federate your identity provider's JWT so every key request authenticates *as the
  signed-in user*, not as your app. Supported providers: **Supabase Auth**, **Clerk**, **Okta**, and **Auth0**
  (any OIDC-compliant provider works).

```typescript
// Access key (default) — reads CS_* env vars, no config needed
const client = await Encryption({ schemas: [users] });

// OIDC federation — every ZeroKMS request authenticates as the end user
const client = await Encryption({
  schemas: [users],
  config: { authStrategy: OidcFederationStrategy.create(workspaceCrn, () => getUserJwt()) },
});
```

→ [Authentication][auth]

### 🗝️ Built-in key management

Key management is built in, powered by [ZeroKMS][zerokms] — no AWS KMS to wire up, no key vault to run,
no rotation schedule to babysit:

- **A unique key for every value** — not one key per table or per database.
- **Automatic key rotation** — handled for you, with zero downtime.
- **CipherStash can never see your keys.** Keys are *derived inside your application*; neither plaintext
  keys nor plaintext data ever leave your infrastructure.
- **Fast at scale** — bulk key operations handle up to 10,000 keys in a single call, up to 14× faster
  than AWS KMS at peak ([benchmarks][benches]).
- **Every decryption is logged** — a built-in audit trail of who decrypted what, and when.

> **CipherStash never sees your plaintext — or your keys.** Data is encrypted in your app with a unique
> key per value, and keys are derived inside your application via [ZeroKMS][zerokms] — so a database
> breach leaks only ciphertext. [See the security architecture →][security-architecture]

## Advanced features

### 👤 Identity-locking encryption

Building on OIDC federation, you can bind a record's encryption key to the end user's identity, so only
*that* user can decrypt their data: `.withLockContext({ identityClaim })` ties the data key to a claim in
the user's JWT, enforced cryptographically by ZeroKMS.

```typescript
// Bind the data key to a claim — the same claim is required to decrypt
await client
  .encrypt("alice@example.com", { table: users, column: users.email })
  .withLockContext({ identityClaim: ["sub"] });
```

→ [Identity-locking encryption][identity]

### 🗂️ Keysets for multitenancy & sovereignty

Partition your keys into **keysets** — independent key hierarchies within a single workspace. Give each
tenant its own keyset (`config.keyset`) for cryptographic tenant isolation: every encrypt, decrypt, and
query is scoped to a keyset, so revoking a client's access to a keyset makes that tenant's data
unreadable until the grant is restored — without re-architecting your app. [Keysets →][keysets]

## Encrypted fields. Real queries. Your tools.

The `email` column below is stored as ciphertext with a unique key per row — and the search still works,
because the query runs on the ciphertext. No decrypt-and-scan, no query rewrites.

**Supabase** — same Supabase.js calls; the wrapper introspects your schema, encrypts filters on the way
in, and decrypts results on the way out:

```typescript
const db = await encryptedSupabase(supabaseUrl, supabaseKey);

const { data } = await db.from("users")
  .select("id, name, email")
  .eq("email", "alice@acme.com"); // encrypted equality — runs on ciphertext
```

**Prisma Next** — declare encrypted columns in `schema.prisma`, query with type-safe operators:

```prisma
model User {
  id    String @id
  email cipherstash.TextSearch()
}
```

```typescript
const rows = await db.orm.public.User
  .where((u) => u.email.eqlMatch("acme.com"))
  .all();
```

**Drizzle** — encrypted column types in your table, auto-encrypting operators in your queries:

```typescript
export const usersTable = pgTable("users", {
  id: integer("id").primaryKey(),
  email: types.TextSearch("email"), // → eql_v3_text_search — the type is the config
});

const results = await db.select().from(usersTable)
  .where(await ops.matches(usersTable.email, "acme.com"));
```

## How it works

<p align="center">
  <picture>
    <!-- Dark theme · narrow viewport (mobile) -->
    <source media="(prefers-color-scheme: dark) and (max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-dark.svg">
    <!-- Dark theme · wide viewport (desktop) -->
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-dark.svg">
    <!-- Light theme · narrow viewport (mobile) -->
    <source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-stacked-light.svg">
    <!-- Light theme · wide viewport (desktop) — universal fallback (npm, older renderers) -->
    <img alt="CipherStash architecture: encryption and decryption happen in your TypeScript app; only ciphertext (EQL JSON) is stored in your PostgreSQL database. ZeroKMS issues a unique key per value, derived in your app. Plaintext and keys never reach CipherStash, and every decryption is logged for audit." width="880" src="https://raw.githubusercontent.com/cipherstash/stack/main/docs/images/architecture-light.svg">
  </picture>
</p>

Encryption happens in your application. Ciphertext is stored as an [EQL][eql] payload in your database;
plaintext and keys never reach CipherStash. Per-value keys are issued in bulk by ZeroKMS (so millions
of unique keys stay fast), and every decryption is logged for compliance.

→ [Security architecture][security-architecture] · [ZeroKMS][zerokms]

## Performance

Encrypted queries stay fast — latency is flat from 10k to 10M rows. Measured on EQL v3 in [cipherstash/benches][benches]:

| Operation | Median latency (up to 10M rows) |
|---|---|
| Equality lookup | ~0.1 ms |
| Range query | ~0.5 ms |
| JSON field equality | ~0.1 ms |

<!-- TODO: embed a purpose-built latency chart here (theme-aware light/dark SVG pair in docs/images/,
     same treatment as the architecture diagram): one line per query family (equality, range, JSON)
     staying flat from 10k → 10M rows, regenerated from cipherstash/benches data. The charts committed
     to the benches repo are internal-report style (matplotlib) and not README-quality.
     See docs/plans/readme-visual-assets.md → Asset 3. -->

## Why CipherStash

- **Trusted data access** — only your end-users can access their sensitive data, enforced cryptographically.
- **Shrink the blast radius** — a breached vulnerability exposes only what one user can decrypt, not your whole table.
- **Audit trail built in** — every decryption event is recorded, no extra tooling to bolt on.
- **Meet compliance faster** — exceed the encryption requirements of SOC 2 and ISO 27001, with FIPS-compliant
  cryptography and BYOK for teams that need it.

## FAQ

<details>
<summary><b>Can CipherStash ever see my data, or my encryption keys?</b></summary>

No, never. Encryption and decryption happen in your application, and keys are derived within your own
environment. Plaintext and keys never leave your control and never reach CipherStash.
</details>

<details>
<summary><b>How well does it scale?</b></summary>

Latency stays flat as data grows — exact-match lookups hold at ~0.1 ms and range queries at ~0.5 ms from
10k up to 10M rows ([cipherstash/benches][benches]). ZeroKMS handles keys in bulk (up to 10,000 per
call), so key management isn't the bottleneck.
</details>

<details>
<summary><b>What does migration look like?</b></summary>

Install EQL on your Postgres database (`npx stash init` and the [quick starts](#quick-starts) handle
this), declare the columns you want protected with the encrypted type that fits each one (for example
`eql_v3_text_match` for searchable text or `eql_v3_integer_ord` for range queries), and encrypt values in
your app before writing. You can adopt it column-by-column — no big-bang rewrite — and your existing
Postgres indexes keep working.
</details>

<details>
<summary><b>Do I have to change how I write queries?</b></summary>

Barely. You keep your query builder: Supabase.js filters work unchanged, and Drizzle and Prisma Next
add encrypted-aware operators (`ops.eq`, `ops.matches`, `eqlMatch`, …) that take plaintext and encrypt
it for you. There are no SQL rewrites.
</details>

<details>
<summary><b>Do I need to run a KMS or key vault?</b></summary>

No. Key management is built in through ZeroKMS. If you want to control the root key, Bring Your Own Key
lets you root it in your own KMS.
</details>

<details>
<summary><b>Does it work with Supabase Auth and Row Level Security?</b></summary>

Yes. It integrates with Supabase Auth and runs alongside RLS — it complements them, it doesn't replace
them.
</details>

<details>
<summary><b>I already use Row Level Security — do I need this?</b></summary>

RLS and CipherStash solve different problems, and they're strongest together. RLS decides which rows a
role may query, but the data underneath is plaintext — so anything that bypasses RLS reveals it in the
clear: a leaked `service_role` key, a misconfigured policy, a SQL injection running as an elevated role,
a stolen backup, or the database host itself. CipherStash stores only ciphertext and keeps the keys
outside the database, so those same bypasses reveal nothing readable. Keep RLS for authorization; add
CipherStash so a bypass never becomes a breach.
</details>

<details>
<summary><b>Is there a free tier?</b></summary>

Yes — a free developer tier, so you can build encryption in from day one.
</details>

## Start free

Encryption is far cheaper to design in than to retrofit — and it's what unlocks regulated and enterprise
customers. The developer tier is **free**, so you can add encryption from your very first migration:

```bash
npx stash init
```

Signing up is the wizard's first step if you don't have an account yet — or
[create your free account][signup] in the browser first, and `stash init` will pick it up.

## Install

```bash
npm install @cipherstash/stack   # or: yarn / pnpm / bun add @cipherstash/stack
```

> [!IMPORTANT]
> **Opt out of bundling `@cipherstash/stack`.** It uses native Node.js features (a Rust FFI module) and the
> native `require`. For edge and serverless runtimes (Cloudflare Workers, Deno, Bun), use the bundler-friendly
> `@cipherstash/stack/wasm-inline` entry instead. [Bundling guide →][bundling]

**Requirements:** Node.js ≥ 22.

## Documentation & community

- 📚 [Documentation][docs] · [Quickstart][quickstart] · [SDK reference][reference]
- 🧩 [Example apps][examples]
- 💬 [Discord community][discord]

## Contributing · Security · License

Contributions are welcome — see [CONTRIBUTE.md][contribute]. For our security policy and responsible
disclosure, see [SECURITY.md][security-policy]. [MIT licensed][license].

<!-- Link definitions — keep all URLs here. CipherStash links carry README UTM params. -->
[signup]: https://cipherstash.com/signup?utm_source=github&utm_medium=stack_readme
[docs]: https://cipherstash.com/docs/stack?utm_source=github&utm_medium=stack_readme
[quickstart]: https://cipherstash.com/docs/stack/quickstart?utm_source=github&utm_medium=stack_readme
[reference]: https://cipherstash.com/docs/stack/reference?utm_source=github&utm_medium=stack_readme
[encryption]: https://cipherstash.com/docs/stack/cipherstash/encryption?utm_source=github&utm_medium=stack_readme
[searchable-encryption]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_readme
[schema]: https://cipherstash.com/docs/stack/cipherstash/encryption/schema?utm_source=github&utm_medium=stack_readme
[encrypt-decrypt]: https://cipherstash.com/docs/stack/cipherstash/encryption/encrypt-decrypt?utm_source=github&utm_medium=stack_readme
[model-ops]: https://cipherstash.com/docs/stack/cipherstash/encryption/encrypt-decrypt?utm_source=github&utm_medium=stack_readme#model-operations
[supabase]: https://cipherstash.com/docs/stack/cipherstash/encryption/supabase?utm_source=github&utm_medium=stack_readme
[drizzle]: https://cipherstash.com/docs/stack/cipherstash/encryption/drizzle?utm_source=github&utm_medium=stack_readme
[prisma-next]: https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next?utm_source=github&utm_medium=stack_readme
[dynamodb]: https://cipherstash.com/docs/stack/cipherstash/encryption/dynamodb?utm_source=github&utm_medium=stack_readme
[identity]: https://cipherstash.com/docs/stack/cipherstash/encryption/identity?utm_source=github&utm_medium=stack_readme
[security-architecture]: https://cipherstash.com/docs/stack/reference/security-architecture?utm_source=github&utm_medium=stack_readme
[zerokms]: https://cipherstash.com/docs/stack/cipherstash/kms?utm_source=github&utm_medium=stack_readme
[bundling]: https://cipherstash.com/docs/stack/deploy/bundling?utm_source=github&utm_medium=stack_readme
[query-equality]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_readme#equality
[query-match]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_readme#free-text-search
[query-range]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_readme#range-and-ordering
[query-json]: https://cipherstash.com/docs/stack/cipherstash/encryption/searchable-encryption?utm_source=github&utm_medium=stack_readme#json
[auth]: https://cipherstash.com/docs/stack/cipherstash/encryption/identity?utm_source=github&utm_medium=stack_readme
[keysets]: https://cipherstash.com/docs/stack/cipherstash/kms?utm_source=github&utm_medium=stack_readme#keysets
[benches]: https://github.com/cipherstash/benches
[eql]: https://github.com/cipherstash/encrypt-query-language
[discord]: https://discord.gg/5qwXUFb6PB
[examples]: https://github.com/cipherstash/stack/tree/main/examples
[contribute]: https://github.com/cipherstash/stack/blob/main/CONTRIBUTE.md
[security-policy]: https://github.com/cipherstash/stack/blob/main/SECURITY.md
[license]: https://github.com/cipherstash/stack/blob/main/LICENSE.md
