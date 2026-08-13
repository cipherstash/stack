#!/usr/bin/env bash
set -euo pipefail

# Compare function call coverage between SQL and Rust tests
# Run from project root: ./tools/compare-function-calls.sh [sql-calls.json] [rust-calls.json]

SQL_CALLS="${1:-sql-function-calls.json}"
RUST_CALLS="${2:-rust-function-calls.json}"

echo "# Function Call Coverage Comparison"
echo ""
echo "SQL Tests → Rust Tests"
echo ""

# Get functions only in SQL tests
echo "## Functions ONLY in SQL tests (missing in Rust):"
comm -23 \
  <(jq -r '.functions[] | .function' "$SQL_CALLS" | sort) \
  <(jq -r '.functions[] | .function' "$RUST_CALLS" | sort) \
  | while read -r func; do
      calls=$(jq -r ".functions[] | select(.function == \"$func\") | .calls" "$SQL_CALLS")
      echo "- \`$func\` ($calls calls in SQL tests)"
    done

echo ""
echo "## Functions in BOTH test suites:"
comm -12 \
  <(jq -r '.functions[] | .function' "$SQL_CALLS" | sort) \
  <(jq -r '.functions[] | .function' "$RUST_CALLS" | sort) \
  | while read -r func; do
      sql_calls=$(jq -r ".functions[] | select(.function == \"$func\") | .calls" "$SQL_CALLS")
      rust_calls=$(jq -r ".functions[] | select(.function == \"$func\") | .calls" "$RUST_CALLS")
      echo "- \`$func\` (SQL: $sql_calls, Rust: $rust_calls)"
    done

echo ""
echo "## Functions ONLY in Rust tests (new coverage):"
comm -13 \
  <(jq -r '.functions[] | .function' "$SQL_CALLS" | sort) \
  <(jq -r '.functions[] | .function' "$RUST_CALLS" | sort) \
  | while read -r func; do
      calls=$(jq -r ".functions[] | select(.function == \"$func\") | .calls" "$RUST_CALLS")
      echo "- \`$func\` ($calls calls in Rust tests)"
    done
