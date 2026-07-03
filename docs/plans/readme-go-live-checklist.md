# Root README — go-live checklist

The refreshed root `README.md` is **doc-driven**: it describes the EQLv3-based Stack slightly ahead of
current code capabilities. Before the README merges to `main` (or is published anywhere), confirm each
claim below is actually implemented and each placeholder is resolved.

## API surfaces shown in code examples

- [ ] **Drizzle EQL v3 types** — the sizzle uses `types.TextMatch("email")` in `pgTable` (mirroring the
  `types` namespace from stack PR [#541](https://github.com/cipherstash/stack/pull/541)). The current
  published `@cipherstash/drizzle` API is still the SEM-style `encryptedType<string>("email", { … })`
  options object — confirm the v3 `types` surface has shipped and the import path/namespace name match.
- [ ] **Supabase** — `encryptedSupabase({ encryptionClient, supabaseClient })` with transparent
  `.ilike()` on encrypted columns (encrypt-filters-in / decrypt-results-out), as published.
- [ ] **Prisma Next** — `cipherstash.EncryptedString()` in `schema.prisma` and the `cipherstashIlike`
  operator, as published.
- [ ] **Raw SDK** — the searchable-encryption section shows
  `import { encryptedTable, types } from "@cipherstash/stack/eql/v3"` with `types.TextMatch` /
  `types.Int4Ord`; confirm the subpath and namespace ship as in PR #541, and that quick-start guides
  cover this surface.

## EQL v3 claims

- [ ] **Domain type names** — `eql_v3.text_match`, `eql_v3.text_eq`, `eql_v3.int4_ord`, `eql_v3.json`
  (CREATE TABLE example + FAQ) match the exact names on the `eql_v3` branch of
  `encrypt-query-language` (messaging brief flags these as illustrative until confirmed).
- [ ] **"The type is the configuration"** — ORMs genuinely need no per-column search config; raw `pg`
  manual client schema is the only exception.
- [ ] **Scalar coverage** — "text, integers, floats, numerics, dates, timestamps, booleans, and JSON"
  are all available (note: int8/bigint was still pending lossless FFI I/O as of PR #541).
- [ ] **Standard Postgres indexes** — the "stays indexable with standard Postgres indexes" claim holds
  for the shipped types.

## CLI & auth claims

- [ ] **`npx stash init`** — signs up users without an account as its first step (Start free CTA), and
  installs EQL on the target database (FAQ migration answer).
- [ ] **Device auth** — `npx stash auth login` browser flow + local profile, as described.
- [ ] **OIDC federation providers** — Supabase Auth, Clerk, Okta, and Auth0 all verified working.

## Key management claims

- [ ] **Automatic key rotation** — shipped and accurate to describe as "handled for you, zero downtime".
- [ ] **Keysets** — per-tenant keysets, revocation ("renders tenant data permanently unreadable"), and
  region pinning for sovereignty are shipped (Advanced features section).
- [ ] **Audit logging** — "every decryption is logged" is true for all auth modes.

## Performance section

- [ ] **Numbers refreshed on EQL v3** — current figures come from the EQL 2.3 run in
  `cipherstash/benches`; re-run on v3 before launch ([CIP-3296](https://linear.app/cipherstash/issue/CIP-3296)).
- [ ] **Flat-latency chart** embedded ([CIP-3361](https://linear.app/cipherstash/issue/CIP-3361),
  spec: Asset 3 in `readme-visual-assets.md`).

## Links & assets (mechanical, pre-merge)

- [ ] **Placeholder doc links** — query-type anchors (`#equality`, `#free-text-search`,
  `#range-and-ordering`, `#json`), `[auth]` page, and `[keysets]` anchor all resolve once the EQL v3
  docs land (marked with a TODO comment above the link definitions).
- [ ] **Architecture diagram URLs** — restore the absolute
  `https://raw.githubusercontent.com/cipherstash/stack/main/…` prefix on the four `<picture>` paths
  (currently relative for PR preview; TODO comment in place, also flagged in `readme-visual-assets.md`).
- [ ] **Social preview card** — upload the 1280×640 og:image via repo Settings → General → Social
  preview, and set the About description to the brief's one-liner ("Searchable, application-level
  encryption for building privacy-first apps.") — it doubles as the `og:description`. Verify with a
  fresh link paste (spec: Asset 4 in `readme-visual-assets.md`).
