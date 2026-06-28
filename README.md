<div align="center">
  <a href="https://cipherstash.com?utm_source=github&utm_medium=stack_readme">
    <img alt="CipherStash" width="128" height="128" src="https://cipherstash.com/brand/cipherstash-logo-dark.svg">
  </a>
  <h1>CipherStash Stack for TypeScript</h1>

  <p><b>Field-level encryption for TypeScript apps — search encrypted data without decrypting it, with
  zero-knowledge key management. Every value gets its own key, and your keys never leave your AWS KMS.</b></p>

  <a href="https://www.npmjs.com/package/@cipherstash/stack"><img alt="npm version" src="https://img.shields.io/npm/v/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://www.npmjs.com/package/@cipherstash/stack"><img alt="npm downloads" src="https://img.shields.io/npm/dm/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/stargazers"><img alt="GitHub stars" src="https://img.shields.io/github/stars/cipherstash/stack?style=for-the-badge&labelColor=000000"></a>
  <a href="https://cipherstash.com/docs/stack?utm_source=github&utm_medium=stack_readme"><img alt="Docs" src="https://img.shields.io/badge/Docs-333333.svg?style=for-the-badge&logo=readthedocs&labelColor=333"></a>
  <a href="https://discord.gg/5qwXUFb6PB"><img alt="Discord" src="https://img.shields.io/badge/Join%20the%20community-blueviolet.svg?style=for-the-badge&logo=Discord&labelColor=000000"></a>
  <a href="https://github.com/cipherstash/stack/blob/main/LICENSE.md"><img alt="License" src="https://img.shields.io/npm/l/@cipherstash/stack.svg?style=for-the-badge&labelColor=000000"></a>

  <div>⭐ Star this repo if encryption you can actually query is your thing!</div>
</div>

<br/>

> **CipherStash never sees your plaintext.** Data is encrypted in your app with a unique key per value via
> [ZeroKMS][zerokms], rooted in your own [AWS KMS][aws-kms] — so a database breach leaks only ciphertext.
> [See the security architecture →][security-architecture]

## Quick start

You'll need a free CipherStash account to provision keys and a workspace — it takes about a minute.

**1. Create a free account** → **[cipherstash.com/signup][signup]**

**2. Initialize your project** — the wizard authenticates you, builds an encryption schema, and wires up your database:

```bash
npx stash init
```

**3. Encrypt, search, and decrypt:**

```typescript
import { Encryption } from "@cipherstash/stack";
import { encryptedTable, encryptedColumn } from "@cipherstash/stack/schema";

// Define which columns are encrypted — and how you want to query them
const users = encryptedTable("users", {
  email: types.TextSearch("email"), // equality + order/range + free-text search
});

const client = await Encryption({ schemas: [users] });

// Encrypt → store the ciphertext in your own database
const enc = await client.encrypt("alice@example.com", { table: users, column: users.email });

// Search WITHOUT decrypting — the part nobody else does
const term = await client.encryptQuery("alice@example.com", {
  table: users, column: users.email, queryType: "equality",
});
// → drop term.data straight into your WHERE clause

// Decrypt when you need the plaintext back
const dec = await client.decrypt(enc.data);
```

Prefer the long version? Follow the **[5-minute quickstart →][quickstart]**

## What's in the Stack

Three building blocks for protecting sensitive data in TypeScript apps — use one, or all three together.

### 🔐 Searchable encryption

Encrypt individual fields and still run real queries against them — exact match, full-text search,
range/sorting, and encrypted JSONB — all on ciphertext, in PostgreSQL.

```typescript
const users = encryptedTable("users", {
  email: encryptedColumn("email").equality().freeTextSearch().orderAndRange(),
  metadata: encryptedColumn("metadata").searchableJson(), // encrypted JSONB queries
});
```

→ [Searchable encryption][searchable-encryption] · [Schema][schema] · [Encrypt & decrypt][encrypt-decrypt] · [Bulk & model operations][model-ops]

### 🔗 ORM & database integrations

Drop encryption into the stack you already use. Type-safe operators let you query encrypted columns
exactly like normal ones.

| Integration | Status | Guide |
|---|---|---|
| PostgreSQL (raw SQL) | ✅ | [Docs][encryption] |
| Supabase | ✅ | [Docs][supabase] |
| Drizzle ORM | ✅ | [Docs][drizzle] |
| Prisma (Prisma Next) | ✅ | [Docs][prisma-next] |
| DynamoDB | ✅ | [Docs][dynamodb] |

```typescript
// Drizzle: query encrypted columns with auto-encrypting operators
const results = await db.select().from(usersTable)
  .where(await ops.eq(usersTable.email, "alice@example.com"));
```

### 👤 Identity-aware encryption

Bind decryption to a user's identity so only *that* user can read their data — a valid JWT from your
identity provider is required to decrypt. Clerk ships a drop-in Next.js middleware today; any OIDC
provider works through the `LockContext` primitive.

| Provider | Support |
|---|---|
| Clerk (Next.js middleware) | ✅ Drop-in |
| Any OIDC provider (Auth0, Okta, Supabase Auth, …) | ✅ via JWT / `LockContext` |

```typescript
import { LockContext } from "@cipherstash/stack/identity";

const lc = await new LockContext().identify(userJwt);
const enc = await client.encrypt("ssn", { table: users, column: users.ssn })
  .withLockContext(lc.data);
```

→ [Identity-aware encryption][identity]

> The Stack also ships a `stash` CLI for auth, schema, and database setup. See the [SDK reference][reference].

## How it works

Encryption happens in your application. Ciphertext is stored as an [EQL][eql] JSON payload in your database;
plaintext and root keys never reach CipherStash. Per-value keys are issued in bulk by ZeroKMS (so millions
of unique keys stay fast), and every decryption is logged for compliance.

→ [Security architecture][security-architecture] · [ZeroKMS][zerokms]

## Why CipherStash

- **Trusted data access** — only your end-users can access their sensitive data, enforced cryptographically.
- **Shrink the blast radius** — a breached vulnerability exposes only what one user can decrypt, not your whole table.
- **Meet compliance faster** — exceed the encryption requirements of SOC 2 and ISO 27001, with an audit trail of every decryption.

## Install

```bash
npm install @cipherstash/stack   # or: yarn / pnpm / bun add @cipherstash/stack
```

> [!IMPORTANT]
> **Opt out of bundling `@cipherstash/stack`.** It uses native Node.js features (a Rust FFI module) and the
> native `require`. [Bundling guide →][bundling]

**Requirements:** Node.js ≥ 18.

## Migrating from Protect.js

> [!NOTE]
> **`@cipherstash/protect` (Protect.js) is now legacy and in maintenance mode.** It still receives critical
> security fixes, but all new development has moved to `@cipherstash/stack`. New projects should use the
> Stack; existing Protect.js users can migrate with the mapping below.

| `@cipherstash/protect` | `@cipherstash/stack` |
|---|---|
| `protect(config)` | `Encryption(config)` |
| `csTable` / `csColumn` | `encryptedTable` / `encryptedColumn` |
| `@cipherstash/protect/identify` | `@cipherstash/stack/identity` |

Method signatures and the `Result` (`data` / `failure`) pattern are unchanged. [Full migration guide →][reference]

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
[eql]: https://github.com/cipherstash/encrypt-query-language
[aws-kms]: https://docs.aws.amazon.com/kms/latest/developerguide/overview.html
[discord]: https://discord.gg/5qwXUFb6PB
[examples]: ./examples
[contribute]: ./CONTRIBUTE.md
[security-policy]: ./SECURITY.md
[license]: ./LICENSE.md
