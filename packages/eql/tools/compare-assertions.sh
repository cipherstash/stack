#!/usr/bin/env bash
set -euo pipefail

# Compare assertion counts and show migration progress
# Run from project root: ./tools/compare-assertions.sh

# Count SQL assertions by pattern type
ASSERT_COUNT=$(find src -name "*_test.sql" -exec grep -c "ASSERT " {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
PERFORM_COUNT=$(find src -name "*_test.sql" -exec grep -c "PERFORM assert_" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
SELECT_COUNT=$(find src -name "*_test.sql" -exec grep -c "SELECT.*=" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
SQL_COUNT=$((ASSERT_COUNT + PERFORM_COUNT + SELECT_COUNT))

# Count Rust assertions (simpler pattern)
RUST_ASSERT=$(find rust-tests/tests -name "*.rs" -exec grep -c "assert" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
RUST_EXPECT=$(find rust-tests/tests -name "*.rs" -exec grep -c "expect(" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum+0}')
RUST_COUNT=$((RUST_ASSERT + RUST_EXPECT))

echo "# Assertion Coverage Progress"
echo ""
echo "- **SQL Tests:** $SQL_COUNT assertions"
echo "- **Rust Tests:** $RUST_COUNT assertions"
echo ""

PERCENTAGE=0
if [ "$SQL_COUNT" -gt 0 ]; then
    PERCENTAGE=$(( (RUST_COUNT * 100) / SQL_COUNT ))
fi

echo "**Coverage:** $PERCENTAGE% ($RUST_COUNT/$SQL_COUNT)"
echo ""

if [ "$RUST_COUNT" -ge "$SQL_COUNT" ]; then
    echo "✅ Rust test assertions meet or exceed SQL test coverage!"
else
    REMAINING=$((SQL_COUNT - RUST_COUNT))
    echo "⚠️  $REMAINING assertions remaining to port"
fi
