#!/usr/bin/env bash
set -euo pipefail

# Count assertions in SQL and Rust tests
# Run from project root: ./tools/count-assertions.sh

count_sql_assertions() {
    local total=0
    local file_count=0

    echo "# SQL Test Assertions"
    echo ""
    echo "| File | ASSERT | PERFORM assert_* | SELECT checks | Total |"
    echo "|------|--------|------------------|---------------|-------|"

    while IFS= read -r file; do
        # Count different assertion types
        assert_count=$(grep -c "ASSERT " "$file" 2>/dev/null || true)
        perform_assert=$(grep -c "PERFORM assert_" "$file" 2>/dev/null || true)
        select_checks=$(grep -c "SELECT.*=" "$file" 2>/dev/null || true)

        file_total=$((assert_count + perform_assert + select_checks))
        total=$((total + file_total))
        file_count=$((file_count + 1))

        rel_path=${file#./src/}
        echo "| \`$rel_path\` | $assert_count | $perform_assert | $select_checks | $file_total |"
    done < <(find src -name "*_test.sql" -type f | sort)

    echo ""
    echo "**Total SQL assertions:** $total across $file_count files"
}

count_rust_assertions() {
    local total=0
    local file_count=0

    echo ""
    echo "# Rust Test Assertions"
    echo ""
    echo "| File | assert* | expect* | is_err/is_ok | Total |"
    echo "|------|---------|---------|--------------|-------|"

    while IFS= read -r file; do
        # Count different assertion types
        assert_count=$(rg -c "assert(!|_eq|_ne)" "$file" 2>/dev/null || echo 0)
        expect_count=$(rg -c "\.expect\(" "$file" 2>/dev/null || echo 0)
        result_checks=$(rg -c "\.is_(err|ok)\(" "$file" 2>/dev/null || echo 0)

        file_total=$((assert_count + expect_count + result_checks))
        total=$((total + file_total))
        file_count=$((file_count + 1))

        rel_path=${file#./rust-tests/}
        echo "| \`$rel_path\` | $assert_count | $expect_count | $result_checks | $file_total |"
    done < <(find rust-tests/tests -name "*.rs" -type f 2>/dev/null | sort)

    if [ $file_count -eq 0 ]; then
        echo "| *(no Rust tests yet)* | 0 | 0 | 0 | 0 |"
    fi

    echo ""
    echo "**Total Rust assertions:** $total across $file_count files"
}

# Main execution
{
    echo "# Assertion Count Report"
    echo ""
    echo "Generated: $(date +%Y-%m-%d)"
    echo ""
    count_sql_assertions
    count_rust_assertions
} | tee docs/assertion-counts.md
