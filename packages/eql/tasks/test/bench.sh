#!/usr/bin/env bash
#MISE description="Run benchmark / regression / scale SQLx tests (--features bench)"
#USAGE flag "--postgres <version>" help="PostgreSQL version" default="17" {
#USAGE   choices "14" "15" "16" "17"
#USAGE }

set -euo pipefail

POSTGRES_VERSION=${usage_postgres}

echo "=========================================="
echo "Running EQL Bench Suite"
echo "PostgreSQL Version: $POSTGRES_VERSION"
echo "=========================================="

"$(dirname "$0")/../postgres/check_container.sh" "${POSTGRES_VERSION}"

# Prep the SQLx test DB exactly like the standard suite (test:sqlx): build EQL,
# copy it into migrations, migrate, AND regenerate the gitignored per-type
# fixtures. The fixtures are include_str!'d into the test binary at COMPILE time
# by #[sqlx::test(fixtures(...))], so they MUST exist on disk before `cargo test`
# compiles. This script previously hand-rolled build+cp+migrate but omitted
# fixture generation; once fixtures became generated/gitignored the bench binary
# stopped compiling (couldn't read tests/sqlx/fixtures/eql_v3_*.sql). Reusing
# prep keeps bench in lockstep with test:sqlx and prevents that drift recurring.
mise run --output prefix test:sqlx:prep

echo "Running bench tests (cargo test --features bench)..."
(cd tests/sqlx && cargo test --features bench)
