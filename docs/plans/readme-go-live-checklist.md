# Root README — go-live checklist

The refreshed root `README.md` started **doc-driven** — written slightly ahead of the code. EQL v3 has
since shipped, and the code examples were re-verified against `main` when the branch was rebased
(2026-07-30). What remains below is the pre-merge tail: link verification, benchmark refresh, and the
social preview card.

## API surfaces shown in code examples — ✅ verified against `main`

- [x] **Drizzle** — `types.TextSearch("email")` in `pgTable` and `ops.matches(...)` match
  `@cipherstash/stack-drizzle` (there are no `like`/`ilike` operators on the v3 surface, by design).
- [x] **Supabase** — `await encryptedSupabase(supabaseUrl, supabaseKey)` (introspects the database at
  connect time) with `.from("users").select(...).eq(...)`. The sizzle uses an equality filter because
  `matches()` is unavailable through PostgREST on EQL 3.0.2.
- [x] **Prisma Next** — `cipherstash.TextSearch()` in `schema.prisma` and the
  `db.orm.public.User.where((u) => u.email.eqlMatch(...))` operator surface
  (`@cipherstash/stack-prisma`).
- [x] **Raw SDK** — `import { encryptedTable, types } from "@cipherstash/stack/v3"` with
  `types.TextMatch` / `types.IntegerOrd`.
- [x] **Auth** — `config.authStrategy` (`config.strategy` is deprecated) with
  `OidcFederationStrategy.create(crn, () => getJwt())`, matching
  `packages/stack/__tests__/lock-context.test.ts`.

## EQL v3 claims — ✅ verified against `main`

- [x] **Domain type names** — column domains live in `public`: `eql_v3_text_match`, `eql_v3_text_eq`,
  `eql_v3_integer_ord`, `eql_v3_json_search` (the `eql_v3` schema holds the `query_*` domains and
  functions). CREATE TABLE example + FAQ updated to match.
- [x] **"The type is the configuration"** — Drizzle derives the client schema from the table
  (`extractEncryptionSchema`), Prisma from `schema.prisma`, Supabase from database introspection; raw
  `pg` is the only surface needing a hand-written client schema.
- [x] **Scalar coverage** — text, smallint/integer/bigint, real/double, numeric, date, timestamp,
  boolean, and JSON all have `types.*` factories.
- [x] **Standard Postgres indexes** — holds; note the `*OrdOre` domains need a custom operator class
  the installer can't create on cloud-hosted Supabase (plain `Ord` works everywhere).

## CLI & auth claims

- [x] **Device auth** — `stash auth login` is in the command registry (OAuth 2.0 device flow, local
  profile).
- [ ] **`npx stash init`** — confirm sign-up-first flow for users without an account (Start free CTA).
- [ ] **OIDC federation providers** — Supabase Auth, Clerk, Okta, and Auth0 all verified working.

## Key management claims

- [ ] **Automatic key rotation** — shipped and accurate to describe as "handled for you, zero downtime".
- [x] **Keysets** — per-tenant keysets via `config.keyset` and loud failure on revoked access are
  shipped (see `skills/stash-zerokms`). The README's earlier "pin keysets to a region" and
  "permanently unreadable" claims were softened: region residency is a workspace property (part of the
  CRN), not per-keyset, and grant revocation is reversible.
- [ ] **Audit logging** — "every decryption is logged" is true for all auth modes.

## Performance section

- [x] **Numbers refreshed on EQL v3** — verified against the EQL v3 run in `cipherstash/benches`
  (`report/BENCHMARK_REPORT.md` + per-family pages): equality ~0.12–0.14 ms, ORE range (10 rows)
  ~0.5 ms, JSON field equality ~0.1 ms — flat from 10k to 10M rows, matching the README table.
- [ ] **Flat-latency chart** embedded (spec: Asset 3 in `readme-visual-assets.md`).

## Links & assets (mechanical, pre-merge)

- [x] **Doc links** — all docs-site URLs checked against the published docs (2026-07-30), including
  the query-type anchors and the per-integration quick-start slugs. The `[auth]` link now points at
  the identity page (`/docs/stack/cipherstash/encryption/identity`) — there is no standalone
  authentication page.
- [x] **Architecture diagram URLs** — the four `<picture>` paths use the absolute
  `https://raw.githubusercontent.com/cipherstash/stack/main/…` prefix (they will 404 on the PR branch
  and resolve on merge).
- [ ] **Social preview card** — upload the 1280×640 og:image via repo Settings → General → Social
  preview, and set the About description to the brief's one-liner ("Searchable, application-level
  encryption for building privacy-first apps.") — it doubles as the `og:description`. Verify with a
  fresh link paste (spec: Asset 4 in `readme-visual-assets.md`).
