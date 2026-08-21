# SQLx Test Fixtures Schema Documentation

This document defines the structure of the test fixtures used in the SQLx test
suite.

The suite installs the self-contained `eql_v3` surface (via the generated
`001_install_eql.sql` migration) and drives all coverage from **generated**
fixtures. There are no committed table-data fixtures: every fixture is produced
by the Rust fixture framework in `tests/sqlx/src/fixtures/` and is gitignored.

## Generated `eql_v3` fixtures

`mise run fixture:generate:all` (the `generate_all_fixtures` test, run over
`eql-domains::CATALOG`) materialises the fixtures into this directory:

```text
Generated eql_v3 fixtures (gitignored)
  ├── eql_v3_<T>.sql           (jsonb payload — no EQL dependency)
  ├── eql_v3_<T>_doubles.sql   (jsonb payload — duplicate-value variant the
  │                             property suites consume)
  ├── v3_numeric_collision.sql (jsonb payload — no EQL dependency)
  ├── v3_doc_integer.sql       (public.eql_v3_json payload — depends on eql_v3 surface)
  └── v3_ste_vec.sql           (public.eql_v3_json payload — depends on eql_v3 surface)
```

The scalar fixtures (`eql_v3_<T>.sql`) have **no EQL dependency** — `payload` is
plain `jsonb`, so each script applies standalone. The document fixtures
(`v3_doc_integer.sql`, `v3_ste_vec.sql`) depend on the `eql_v3` encrypted-JSONB
surface being installed.

**Regenerated every test run.** `mise run test:sqlx` invokes the generator
before `cargo test`, so a stale generated fixture cannot mask a payload-shape
regression. The generator encrypts in-process via `cipherstash-client`; it
needs a live Postgres plus **both** CipherStash credential pairs in the shell
environment (they are not alternatives): `CS_CLIENT_ACCESS_KEY` +
`CS_WORKSPACE_CRN` for ZeroKMS auth (AutoStrategy) **and** `CS_CLIENT_ID` +
`CS_CLIENT_KEY` for the client key (EnvKeyProvider). Do not hand-edit a
generated file; it is overwritten in place on every run.

**Schema (e.g. `eql_v3_integer`):** Tables live in the dedicated `fixtures` SQL
schema (kept out of the `public`/`eql_v3` type namespaces):
```sql
CREATE SCHEMA IF NOT EXISTS fixtures;
CREATE TABLE fixtures.eql_v3_integer (
  id BIGINT PRIMARY KEY,
  plaintext integer NOT NULL,
  payload jsonb NOT NULL
);
```

**Data:**
- One row per generated value; `id = N` is the Nth generated value.
- `plaintext` values include the type extremes and zero (the matrix comparison
  pivots) plus small/medium/large magnitudes.
- `plaintext` is the **in-table oracle**: consuming tests filter
  `WHERE plaintext = N` directly, so no Rust value constant is shared.
- Each `payload` is a cipherstash-client-encrypted JSONB object converted to
  the v3 envelope via `eql_bindings::from_v2`, carrying `c` (ciphertext),
  `hm` (HMAC equality term), `ob` (ORE block ordering term), `op` (CLLW-OPE
  ordering term — a single hex string, not an array; every ordered family,
  ), `bf` (bloom filter — `text` only), an inert `i` metadata object,
  and `v = 3` (v3 scalars carry no `k` discriminator).

**Used By:**
- the `__scalar_matrix_fixture_shape!` arm in `tests/sqlx/src/matrix.rs`
  (structural verification, generated per type)
- the `eql_v3.<T>` domain operator / property tests, via per-query `payload`
  casts

**Opt-in:** Each consuming test opts in explicitly:
```rust
#[sqlx::test(fixtures(path = "../fixtures", scripts("eql_v3_integer")))]
```

---

## Fixture Naming Conventions

- Use snake_case for fixture file names.
- Generated scalar fixtures follow `eql_v3_<T>.sql`.

## Troubleshooting

**Fixture fails to load:**
- Check the `eql_v3` extension is installed (the `001_install_eql.sql`
  migration runs first).
- Confirm the generator ran — `mise run fixture:generate:all` (or
  `mise run test:sqlx`, which runs it for you).
- Check for SQL syntax errors in the generated file.

**Inconsistent test results:**
- Fixtures are loaded per-test (isolated).
- Verify the CipherStash credentials are present so the generator produces real
  ciphertexts (the suite does not ship static fixtures).
