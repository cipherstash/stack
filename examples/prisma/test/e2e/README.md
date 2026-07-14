# Live PG + EQL v3 + ZeroKMS e2e harness

This directory hosts the live-Postgres + EQL v3 bundle + ZeroKMS end-to-end harness for the @cipherstash/prisma-next example app. Seven `*.e2e.test.ts` files cover one domain or scenario each:

- `num.e2e.test.ts` — `eql_v3_double_ord` round-trip (decrypts to `EncryptedNumber`); `Gt`/`Gte`/`Lt`/`Lte`/`Between`; `cipherstashV3Asc`/`Desc` order-term sort.
- `bigint.e2e.test.ts` — `eql_v3_bigint_ord` round-trip **lossless beyond `Number.MAX_SAFE_INTEGER`** (native `bigint` pipeline); equality + range + in-array + sort.
- `date.e2e.test.ts` — `eql_v3_date_ord` round-trip; date range + order-term sort.
- `bool.e2e.test.ts` — `eql_v3_boolean` is STORAGE-ONLY: round-trip works, the ORM binds no operator methods to the column, and the operator impls throw `EncryptionOperatorError` against it.
- `json.e2e.test.ts` — `eql_v3_json` round-trip + `cipherstashJsonContains` (encrypted jsonb `@>`): top-level, multi-key, array-element, and nested containment, negative cases, and the loud rejection of the match-everything `{}` needle.
- `str-range.e2e.test.ts` — `eql_v3_text_search` carries equality + order/range + free-text on one column: `Eq`, `Gt`, `V3Asc`/`V3Desc`, and `Ilike` (bloom-filter token containment — not SQL `ILIKE`) coexist.
- `mixed.e2e.test.ts` — mixed-domain query issues the minimum framework-SDK crossings (one `bulkEncrypt` seam call per `(table, column)`; operands become ciphertext-free `encryptQuery` terms inside the v3 adapter).

## Local setup

```bash
docker compose -f test/e2e/docker-compose.yml up -d   # from examples/prisma
pnpm --filter @cipherstash/prisma-next-example test:e2e
```

The harness's Vitest global setup (`global-setup.ts`):

1. Verifies the container is up (`pg_isready`) — you own the container lifecycle.
2. Sets `DATABASE_URL` to the harness's local Postgres URL.
3. Runs `prisma-next migrate` against the example app (installs the cipherstash EQL v2 + v3 bundle baselines + the `users` table typed against `public.eql_v3_*` domains; v3 needs no per-column search configs).
4. Requires CipherStash credentials: either `CS_*` variables in `.env` or a local profile from `stash auth login` (device-code flow).

`vitest.config.ts` wires the global setup, scopes the run to `*.e2e.test.ts`, and pins `pool: 'threads'` + `maxWorkers: 1` + `isolate: false` + `fileParallelism: false` so every test file shares one Postgres connection and one CipherStash SDK encryption client (and the SDK isn't asked to run encrypts across files concurrently). Each test file truncates `users` in its `beforeAll` for clean-slate isolation.

## Container

The `docker-compose.yml` runs `postgres:16-alpine` on host port `54329` (non-standard to dodge a developer's locally installed Postgres on `5432`). `tmpfs` data volume so every boot starts from an empty cluster. Container name `cipherstash-e2e-postgres` avoids colliding with the workspace-root `docker-compose.yaml` (port `5433`, used by the framework's own e2e suite).

## v2 limitations that no longer apply

The v2 iteration of this harness carried two known-limitation carve-outs; both are gone on v3:

- **JSON predicates work.** v2's `cipherstashJsonbPathExists` needed client-side STE-VEC selector hashing and was skipped. v3's containment model (`cipherstashJsonContains` → `@>` with an `eql_v3.query_jsonb` term) runs end-to-end — no skips in `json.e2e.test.ts`.
- **BigInt is lossless.** v2 converted `bigint → Number` at the SDK boundary and capped values at `Number.MAX_SAFE_INTEGER`. v3's protect-ffi wire is natively `bigint` (bounds-checked int8), and `bigint.e2e.test.ts` pins a 2^53 + 1 round-trip.

One new-in-v3 refusal is deliberately pinned rather than worked around: `eql_v3_boolean` is storage-only, so `bool.e2e.test.ts` asserts the operator surface is absent/throwing instead of querying it.
