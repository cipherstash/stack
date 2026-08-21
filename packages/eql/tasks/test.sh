#!/usr/bin/env bash
#MISE description="Run all tests (SQLx Rust)"
#USAGE flag "--postgres <version>" help="PostgreSQL version to test against" default="17" {
#USAGE   choices "14" "15" "16" "17"
#USAGE }


set -euo pipefail

POSTGRES_VERSION=${usage_postgres}

echo "=========================================="
echo "Running EQL Test Suite"
echo "PostgreSQL Version: $POSTGRES_VERSION"
echo "=========================================="
echo ""

# Check PostgreSQL is running
"$(dirname "$0")/postgres/check_container.sh" ${POSTGRES_VERSION}

# Build first
echo "Building EQL..."
mise run --output prefix --force build

# The encrypted-domain codegen drift suite (`test:codegen`) is the deprecated
# Python generator's pytest and is intentionally not run here. The Rust
# generator is gated against the hand-written reference by the dedicated
# "Encrypted-domain codegen" CI job (`mise run codegen:parity`).

# Run lints on sqlx tests
echo ""
echo "=============================================="
echo "1/2: Running linting checks on SQLx Rust tests"
echo "=============================================="
mise run --output prefix test:lint

# Run SQLx Rust tests
echo ""
echo "=============================================="
echo "2/2: Running SQLx Rust Tests"
echo "=============================================="
mise run --output prefix test:sqlx

echo ""
echo "=============================================="
echo "✅ ALL TESTS PASSED"
echo "=============================================="
echo ""
echo "Summary:"
echo "  ✓ SQLx Rust lint checks"
echo "  ✓ SQLx Rust tests"
echo ""
