<!-- packages/drizzle/scripts/refresh-eql-v3-sql.md -->
# Refreshing cipherstash-encrypt-v3.sql

Source: cipherstash/encrypt-query-language @ `035952e13fafc87c8a3c89fc7a7ff5447597bdd4`
(branch `dan/eql-types-crate`)

The fixture `__tests__/fixtures/cipherstash-encrypt-v3.sql` is the self-contained
`eql_v3` installer (zero non-comment `eql_v2` references). It defines the four
`text` scalar domains the adapter targets — `eql_v3.text`, `eql_v3.text_eq`,
`eql_v3.text_match`, `eql_v3.text_ord` — plus an additional ORE-variant domain
`eql_v3.text_ord_ore` that the adapter does not target directly. The verification
in step 4 counts only the four primary domains (the `_ord_ore` variant is excluded
by the regex on purpose).

## Steps

1. Clone/checkout the EQL repo at the pinned commit above.
2. Build the release artifacts:
   ```sh
   # sccache must be disabled when building inside a restricted sandbox:
   RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER="" mise run build
   ```
   This regenerates `release/cipherstash-encrypt-v3.sql`. The `text` scalar is a
   hand-written non-integer scalar emitted by the Rust codegen toolchain, so a
   rebuild is required after any EQL update that touches it.
3. Copy the v3 artifact (NOT `cipherstash-encrypt.sql`, which is the v2 installer):
   ```sh
   cp <eql-repo>/release/cipherstash-encrypt-v3.sql \
      packages/drizzle/__tests__/fixtures/cipherstash-encrypt-v3.sql
   ```
4. Verify:
   ```sh
   F=packages/drizzle/__tests__/fixtures/cipherstash-encrypt-v3.sql
   grep -vE '^\s*--' $F | grep -c 'eql_v2'                         # expect 0
   grep -cE 'CREATE DOMAIN eql_v3\.text(_eq|_match|_ord)?\b' $F    # expect 4
   grep -cE 'eq_term|ord_term|match_term' $F                       # > 0
   ```
5. Update the commit SHA above and commit.

## Operator forms (resolves spec §10 — reconciled against the fixture)

The v3 domains DO expose native Postgres operators, but their `(domain, jsonb)`
operator functions coerce the right operand into the domain (e.g.
`eq_term(a) = eq_term(b::text_eq)`). Every domain CHECK requires ciphertext `c`,
which a Protect SEARCH term lacks (`{i,v,hm}` / `…ob` / `…bf`), so the native
form fails `*_check` (SQLSTATE 23514). `v3Dialect` therefore compares **extracted
index terms** — column-side extractors take the column domain, jsonb-side helpers
read the index field straight out of the search term with no coercion:

- `text_eq`    — `eql_v3.eq_term(col) = eql_v3.hmac_256(term::jsonb)`
- `text_ord`   — `eql_v3.ord_term(col) <sym> eql_v3.ore_block_u64_8_256(term::jsonb)`
- `text_match` — `eql_v3.match_term(col) @> eql_v3.bloom_filter(term::jsonb)`

Equality/inequality on `text_eq` go **through the dialect seam** too (the
`dialect.equality` branch in `operators.ts`), not the native `eq()`/`ne()` path —
native `=` would coerce the term into `text_eq` and fail the CHECK.

> Confirmed: equality/inequality go through the dialect seam — plan Task 12
> validated this against the fixture, superseding the earlier Task 6 draft that
> kept `eq`/`ne` on the native path. See `text_eq`, `dialect.equality`, and the
> native `eq()`/`ne()` fallback in `operators.ts`.
