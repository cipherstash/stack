# EQL SQLx Test Framework

Rust-based test framework for EQL (Encrypt Query Language) using SQLx.

## Overview

This test crate provides:
- **Granular test execution**: Run individual tests via `cargo test test_name`
- **Self-documenting fixtures**: SQL files with inline documentation
- **No magic literals**: Selector constants in `src/selectors.rs`
- **Fluent assertions**: Chainable query assertions via `QueryAssertion`

## Architecture

- **SQLx `#[sqlx::test]`**: Automatic test isolation (each test gets fresh database)
- **Fixtures**: generated SQL files in `fixtures/` seed per-test data (see `fixtures/FIXTURE_SCHEMA.md`)
- **Migrations**: a single generated migration in `migrations/`
  - `001_install_eql.sql` - installs the EQL (`eql_v3`) extension (generated, gitignored)
- **Assertions**: Builder pattern for common test assertions
- **Helpers**: Centralized helper functions in `src/helpers.rs`

## Running Tests

```bash
# Run all SQLx tests (builds EQL, runs migrations, tests)
mise run test:sqlx

# Run from project root
mise run test

# Run specific test file
cd tests/sqlx
cargo test --test equality_tests

# Run specific test
cargo test equality_operator_finds_matching_record_hmac -- --nocapture

# All JSONB tests
cargo test jsonb

# All equality tests
cargo test equality

# With output
cargo test -- --nocapture
```

### Generator credentials

`mise run test:sqlx` regenerates the `eql_v3_int4` fixture before running the
suite via `mise run fixture:generate eql_v3_int4`. The generator encrypts
plaintexts in-process using `cipherstash-client` (no Proxy / no Docker
sidecar), so the following CipherStash workspace credentials must be
present in the shell environment when you run it locally or in CI:

- `CS_CLIENT_ACCESS_KEY` + `CS_WORKSPACE_CRN` — preferred, single-token
  bearer credential, picked up by `AutoStrategy::detect()`.
- `CS_CLIENT_ID` + `CS_CLIENT_KEY` — the client-key pair used by
  `EnvKeyProvider` to derive the per-call data keys.

If either set is missing the first call into the generator fails fast
during ZeroKMS handshake with a clear `anyhow` chain naming the missing
variable. Other SQLx tests do not need the `CS_*` variables — only the
fixture-regeneration step does.

## Test Data

### Fixtures

**encrypted_json.sql**: Three base records with structure `{"hello": "world", "n": N}`
- Record 1: n=10
- Record 2: n=20
- Record 3: n=30

**array_data.sql**: One record with array `{"hello": "four", "n": 20, "a": [1,2,3,4,5]}`
- **DEPENDS ON**: `encrypted_json.sql` (requires 'encrypted' table to exist)
- Adds record 4 to the existing table

**config_tables.sql**: Tables for configuration management tests
- Tables: `users`, `blah` with encrypted columns

**constraint_tables.sql**: Tables for constraint testing
- Table: `constrained` with UNIQUE, NOT NULL, CHECK constraints

**encryptindex_tables.sql**: Tables for encryption workflow tests
- Table: `users` with plaintext columns for encryption testing

**match_data.sql**: Test data for LIKE operator tests
- 3 encrypted records with bloom filter indexes


### Selectors

See `src/selectors.rs` for all selector constants:
- `Selectors::ROOT`: $ (root object)
- `Selectors::N`: $.n path
- `Selectors::HELLO`: $.hello path
- `Selectors::ARRAY_ELEMENTS`: $.a[*] (array elements)
- `Selectors::ARRAY_ROOT`: $.a (array root)

Each selector is an MD5 hash that corresponds to the encrypted path query selector.

## Writing Tests

### Basic Test Pattern

```rust
#[sqlx::test(fixtures(path = "../fixtures", scripts("encrypted_json")))]
async fn my_test(pool: PgPool) -> Result<()> {
    let sql = format!(
        "SELECT * FROM encrypted WHERE e = '{}'",
        Selectors::N
    );

    QueryAssertion::new(&pool, &sql)
        .returns_rows()
        .await
        .count(3)
        .await;

    Ok(())
}
```

### Available Assertions

```rust
// Assert query returns at least one row
QueryAssertion::new(&pool, &sql)
    .returns_rows()
    .await;

// Assert query returns exactly N rows
QueryAssertion::new(&pool, &sql)
    .count(3)
    .await;

// Assert query returns specific integer value
QueryAssertion::new(&pool, &sql)
    .returns_int_value(5)
    .await;

// Assert query returns specific boolean value
QueryAssertion::new(&pool, &sql)
    .returns_bool_value(true)
    .await;

// Assert query throws exception
QueryAssertion::new(&pool, &sql)
    .throws_exception()
    .await;
```

### Chainable Assertions

Assertions can be chained together for compact tests:

```rust
QueryAssertion::new(&pool, &sql)
    .returns_rows()
    .await
    .count(5)
    .await;
```

### Helper Functions

Use centralized helpers from `src/helpers.rs`:

```rust
use eql_tests::{get_ore_encrypted, get_ore_encrypted_as_jsonb};

// Get encrypted ORE value for comparison
let ore_term = get_ore_encrypted(&pool, 42).await?;

// Get ORE value as JSONB for operations
let jsonb_value = get_ore_encrypted_as_jsonb(&pool, 42).await?;
```

### Test-Specific Helper Functions

Some test modules include specialized helper functions for their specific use cases:

**Configuration State Helpers** (in `config_tests.rs`):
```rust
// Check if an index exists in EQL configuration with specific state
async fn search_config_exists(
    pool: &PgPool,
    table_name: &str,
    column_name: &str,
    index_name: &str,
    state: &str,
) -> Result<bool>
```

**Schema Inspection Helpers** (in `encryptindex_tests.rs`):
```rust
// Check if a column exists in information_schema
async fn column_exists(
    pool: &PgPool,
    table_name: &str,
    column_name: &str,
) -> Result<bool>

// Check if a column is in the pending columns list for encryption
async fn has_pending_column(
    pool: &PgPool,
    column_name: &str,
) -> Result<bool>
```

## Test Organization
- Tests live in `tests/`
- Fixtures live in `fixtures/`
- Migrations live in `migrations/`
- Tests live in `tests/`
- Fixtures live in `fixtures/`
- Migrations live in `migrations/`

### Test Module Categories

**Operator Tests:**
- `comparison_tests.rs` - Comparison operators (`<`, `>`, `<=`, `>=`)
- `equality_tests.rs` - Equality operators (`=`, `!=`)
- `inequality_tests.rs` - Inequality operators
- `ore_equality_tests.rs` - ORE-specific equality tests
- `ore_comparison_tests.rs` - ORE CLLW comparison tests
- `like_operator_tests.rs` - Pattern matching (`LIKE`, `ILIKE`)
- `containment_tests.rs` - Containment operators (`@>`, `<@`)
- `operator_class_tests.rs` - Operator class definitions

**JSONB Tests:**
- `jsonb_tests.rs` - JSONB functions and structure validation
- `jsonb_path_operators_tests.rs` - JSONB path operators

**Infrastructure Tests:**
- `config_tests.rs` - Configuration management
- `encryptindex_tests.rs` - Encrypted column creation workflows
- `aggregate_tests.rs` - Aggregate functions (COUNT, MAX, MIN, GROUP BY)
- `constraint_tests.rs` - Database constraints on encrypted columns
- `order_by_tests.rs` - ORDER BY with encrypted data

**Index Tests:**
- `index_compare_tests.rs` - Index comparison functions (Blake3, HMAC, ORE variants)
- `operator_compare_tests.rs` - Main compare() function tests
- `specialized_tests.rs` - Specialized cryptographic functions (STE, ORE, Bloom filter)

**Helpers:**
- `test_helpers_test.rs` - Tests for test helper functions


## Dependencies

From `Cargo.toml`:
```toml
[dependencies]
sqlx = { version = "0.8", features = ["runtime-tokio", "postgres", "macros"] }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
anyhow = "1"
```

## Database Configuration

Tests connect to PostgreSQL database configured by SQLx:
- Connection managed automatically by `#[sqlx::test]` macro
- Each test gets isolated database instance
- Fixtures and migrations run before each test
- Database URL: `postgresql://cipherstash:password@localhost:7432/encrypt_test`

## Future Work

- ✅ ~~Convert remaining SQL tests~~ **COMPLETE!**
- Property-based tests: implemented in `tests/encrypted_domain/property/` and
  `crates/eql-domains/src/proptest_invariants.rs`. One unit-level
  **catalog** suite (no DB) plus two integration suites — **fixture** (operator +
  function-double oracles, term-extractor identity, and bloom match smoke over the
  committed real-ciphertext fixtures) and **e2e** (oracle over fresh end-to-end
  encryption each run, `--features proptest-e2e`). See
  `tests/encrypted_domain/property/README.md` for the full structure.
- Performance benchmarks: Measure query performance with encrypted data
- Integration tests: Test with CipherStash Proxy
