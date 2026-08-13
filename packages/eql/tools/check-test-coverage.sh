#!/usr/bin/env bash
set -euo pipefail

# Run all coverage tracking tools and generate report
# Run from project root: ./tools/check-test-coverage.sh

echo "========================================="
echo "Test Coverage Tracking Report"
echo "========================================="
echo ""

# 1. Generate test inventory
echo "## 1. Test Inventory"
./tools/generate-test-inventory.sh
cat docs/test-inventory.md | tail -10
echo ""

# 2. Count assertions
echo "## 2. Assertion Counts"
./tools/count-assertions.sh > /dev/null
./tools/compare-assertions.sh
echo ""

# 3. Function call tracking (requires tests to have run)
if [ -f "sql-function-calls.json" ] && [ -f "rust-function-calls.json" ]; then
    echo "## 3. Function Call Coverage"
    ./tools/compare-function-calls.sh sql-function-calls.json rust-function-calls.json
else
    echo "## 3. Function Call Coverage"
    echo "⚠️  Run SQL and Rust tests first to generate function call data"
    echo ""
    echo "Steps:"
    echo "  1. psql ... -c 'SELECT pg_stat_reset();'"
    echo "  2. mise run test"
    echo "  3. TEST_TYPE=sql ./tools/track-function-calls.sh sql-function-calls.json"
    echo "  4. psql ... -c 'SELECT pg_stat_reset();'"
    echo "  5. cd rust-tests && cargo test"
    echo "  6. TEST_TYPE=rust ./tools/track-function-calls.sh rust-function-calls.json"
fi

echo ""
echo "========================================="
echo "Report complete!"
echo "========================================="
