#!/usr/bin/env bash
set -euo pipefail

# Generate test inventory from SQL test files
# Output: docs/test-inventory.md
# Run from project root: ./tools/generate-test-inventory.sh

OUTPUT="docs/test-inventory.md"

echo "# Test Inventory - SQL to SQLx Migration" > "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Generated: $(date +%Y-%m-%d)" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "| # | SQL Test File | Test Cases | Lines | Status | Rust Test File | Notes |" >> "$OUTPUT"
echo "|---|---------------|------------|-------|--------|----------------|-------|"  >> "$OUTPUT"

count=1
total_tests=0
total_lines=0

# Find all SQL test files
while IFS= read -r sql_file; do
    # Count test cases (DO blocks with ASSERT statements)
    test_cases=$(grep -c 'DO \$\$' "$sql_file" 2>/dev/null || true)

    # Count lines
    lines=$(wc -l < "$sql_file" | tr -d ' ')

    # Extract relative path
    rel_path=${sql_file#./src/}

    # Generate suggested Rust test file path
    rust_file=$(echo "$rel_path" | sed 's/_test\.sql$/_test.rs/' | sed 's/^/rust-tests\/tests\//')

    # Check if Rust file exists
    if [ -f "$rust_file" ]; then
        status="✅ Ported"
    else
        status="❌ TODO"
        rust_file="*TBD*"
    fi

    echo "| $count | \`$rel_path\` | $test_cases | $lines | $status | \`$rust_file\` | |" >> "$OUTPUT"

    total_tests=$((total_tests + test_cases))
    total_lines=$((total_lines + lines))
    count=$((count + 1))
done < <(find src -name "*_test.sql" -type f | sort)

echo "" >> "$OUTPUT"
echo "## Summary" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "- **Total SQL Test Files:** $((count - 1))" >> "$OUTPUT"
echo "- **Total Test Cases:** $total_tests" >> "$OUTPUT"
echo "- **Total Lines:** $total_lines" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "## Usage" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Update this inventory as you port tests:" >> "$OUTPUT"
echo "1. Mark status ✅ when Rust test passes" >> "$OUTPUT"
echo "2. Add Rust test file path" >> "$OUTPUT"
echo "3. Add notes for any deviations" >> "$OUTPUT"
echo "" >> "$OUTPUT"
echo "Regenerate: \`./tools/generate-test-inventory.sh\`" >> "$OUTPUT"

echo "✅ Test inventory generated: $OUTPUT"
