# @cipherstash/prisma-next example

End-to-end demo of [`@cipherstash/prisma-next`](../../packages/prisma-next/README.md): searchable application-layer encryption for Postgres with [Prisma Next](https://www.npmjs.com/package/@prisma-next/cli), using [`@cipherstash/stack`](../../packages/stack/README.md) as the encryption SDK.

A single `User` model with one column per cipherstash codec (string, double, bigint, date, boolean, JSON), exercised end-to-end: insert, equality, free-text search, range, between, in-array, sort, and `decryptAll`-amortised read.

📖 See the [Prisma Next encryption docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) for the full operator reference, security model, and known limitations.

## Layout

| Path                       | Purpose                                                                                       |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| `docker-compose.yml`       | Local Postgres 16 on port 54338.                                                               |
| `prisma/schema.prisma`     | Application schema (one `User` model exercising all six cipherstash codecs).                  |
| `prisma-next.config.ts`    | Wires `cipherstash` into `extensionPacks`.                                                    |
| `src/db.ts`                | One-call setup via `cipherstashFromStack({ contractJson })`.                                  |
| `src/index.ts`             | The demo flow.                                                                                |
| `src/prisma/contract.*`    | Emitted by `pnpm emit`.                                                                       |
| `migrations/`              | Emitted by `pnpm migration:plan`.                                                             |

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
pnpm migration:apply       # installs EQL bundle + your app schema in one sweep (runs `prisma-next migrate`)
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
--- Insert (mixed-codec round-trip) ---
Inserted 4 rows across six cipherstash codecs.

--- cipherstashEq (string equality) ---
Found 1 row(s) for alice@example.com.
  user-0: alice@example.com

--- cipherstashIlike (string free-text-search) ---
Found 3 row(s) matching %@example.com.
  user-0: alice@example.com
  user-1: bob@example.com
  user-2: carol@example.com

--- cipherstashGt (double order-and-range) ---
Found 2 user(s) with salary > 100,000.
  user-1: salary=110000
  user-3: salary=145000

--- cipherstashBetween (date order-and-range) ---
Found 3 user(s) born between 1985 and 1995.

--- cipherstashInArray (bigint equality) ---
Found 2 user(s) whose accountId is in the supplied array.

--- cipherstashInArray (boolean equality-only) ---
Found 3 user(s) with emailVerified = true.

--- cipherstashAsc (bare-column ORDER BY) ---
  user-0: email=alice@example.com
  user-1: email=bob@example.com
  user-2: email=carol@example.com
  user-3: email=dave@otherorg.test
```

## References

- 📖 [Prisma Next encryption docs](https://cipherstash.com/docs/stack/cipherstash/encryption/prisma-next) — the canonical reference.
- [`@cipherstash/prisma-next` package README](../../packages/prisma-next/README.md) — install, subpath exports, quick start.
