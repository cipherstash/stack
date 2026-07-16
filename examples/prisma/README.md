# @cipherstash/prisma-next example

End-to-end demo of [`@cipherstash/prisma-next`](../../packages/prisma-next/README.md): searchable application-layer encryption for Postgres with [Prisma Next](https://www.npmjs.com/package/@prisma-next/cli), using [`@cipherstash/stack`](../../packages/stack/README.md) as the encryption SDK — on **EQL v3**, where every encrypted column is a concrete `public.eql_v3_*` Postgres domain and the constructor you pick *is* the capability set.

A single `User` model with one column per plaintext family, exercised end-to-end: insert, equality, free-text token search, range, between, in-array, encrypted-order-term sort, JSON containment, and `decryptAll`-amortised read.

| Column          | Constructor                       | Domain                      | Query surface                          |
| --------------- | --------------------------------- | --------------------------- | -------------------------------------- |
| `email`         | `cipherstash.EncryptedTextSearch()` | `public.eql_v3_text_search` | equality + order/range + free-text (`eqlMatch`) |
| `salary`        | `cipherstash.EncryptedDoubleOrd()`  | `public.eql_v3_double_ord`  | equality + order/range                 |
| `accountId`     | `cipherstash.EncryptedBigIntOrd()`  | `public.eql_v3_bigint_ord`  | equality + order/range (true `bigint`) |
| `birthday`      | `cipherstash.EncryptedDateOrd()`    | `public.eql_v3_date_ord`    | equality + order/range                 |
| `emailVerified` | `cipherstash.EncryptedBoolean()`    | `public.eql_v3_boolean`     | storage-only (no operators)            |
| `preferences`   | `cipherstash.EncryptedJson()`       | `public.eql_v3_json`        | `eqlJsonContains` (`@>`)               |

📖 See the [Prisma Next encryption docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) for the full operator reference, security model, and known limitations.

## Layout

| Path                       | Purpose                                                                                       |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| `docker-compose.yml`       | Local Postgres 16 on port 54338.                                                               |
| `prisma/schema.prisma`     | Application schema (one `User` model exercising six cipherstash v3 domains).                  |
| `prisma-next.config.ts`    | Wires `cipherstash` into `extensionPacks`.                                                    |
| `src/db.ts`                | One-call setup via `cipherstashFromStackV3({ contractJson })`.                                |
| `src/index.ts`             | The demo flow.                                                                                |
| `src/prisma/contract.*`    | Emitted by `pnpm emit`.                                                                       |
| `migrations/`              | Emitted by `pnpm migration:plan` (app space + the cipherstash EQL bundle baselines).          |

## Prerequisites

1. **Docker** for the bundled Postgres on port 54338 (or any Postgres 16+).
2. **A CipherStash workspace** — sign up at [cipherstash.com](https://cipherstash.com), then run `stash auth login` (PKCE; caches credentials in your OS keychain — no `CS_*` env vars needed in local dev).

## Run it

```bash
cp .env.example .env       # DATABASE_URL points at the bundled Postgres
stash auth login           # one-time, per developer

docker compose up -d
pnpm install
pnpm emit                  # PSL → contract.{json,d.ts}
pnpm migration:plan --name initial
pnpm migration:apply       # installs the EQL bundles + your app schema in one sweep (runs `prisma-next migrate`)
pnpm start                 # runs the demo
```

Teardown:

```bash
docker compose down -v
```

Or, to just verify the example typechecks and emits a valid contract (no database, no workspace):

```bash
pnpm install && pnpm emit && pnpm typecheck
```

## Expected output

```text
--- Insert (mixed-domain round-trip) ---
Inserted 4 rows across six cipherstash v3 domains.

--- eqlEq (text_search equality) ---
Found 1 row(s) for alice@example.com.
  user-0: alice@example.com

--- eqlMatch (text_search free-text tokens) ---
Found 3 row(s) whose email contains example.com.
  user-0: alice@example.com
  user-1: bob@example.com
  user-2: carol@example.com

--- eqlGt (double_ord order-and-range) ---
Found 2 user(s) with salary > 100,000.
  user-1: salary=110000
  user-3: salary=145000

--- eqlBetween (date_ord order-and-range) ---
Found 3 user(s) born between 1985 and 1995.

--- eqlIn (bigint_ord equality) ---
Found 2 user(s) whose accountId is in the supplied array.

--- eql_v3_boolean (storage-only round-trip) ---
  user-2: emailVerified=false

--- eqlJsonContains (encrypted jsonb @>) ---
Found 2 user(s) with a dark-theme preference.
  user-0: {"theme":"dark","notifications":true}
  user-2: {"theme":"dark","notifications":true}

--- eqlAsc (encrypted order-term ORDER BY) ---
  user-0: email=alice@example.com
  user-1: email=bob@example.com
  user-2: email=carol@example.com
  user-3: email=dave@otherorg.test
```

Two v3 behaviours worth noticing in that output:

- **`eqlMatch` is fuzzy bloom-filter token matching** (`eql_v3.contains`), not SQL `ILIKE` — the needle's tokens must appear in the ciphertext's index. Plain literal terms like `example.com` are the idiomatic needle: leading/trailing `%` are stripped for compatibility, while an interior `%` or any `_` throws (the tokenizer would treat them as ordinary characters), as do needles shorter than the match tokenizer length.
- **`eql_v3_boolean` is storage-only.** It round-trips `true`/`false` losslessly but surfaces no search operators — calling one throws `EncryptionOperatorError`. Filter on a searchable column and decrypt the boolean from the result set.

## References

- 📖 [Prisma Next encryption docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) — the canonical reference.
- [`@cipherstash/prisma-next` package README](../../packages/prisma-next/README.md) — install, subpath exports, quick start.
