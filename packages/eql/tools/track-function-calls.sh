#!/usr/bin/env bash
set -euo pipefail

# Track which EQL functions are called during tests
# Output: JSON file with function call counts
# Run from project root: ./tools/track-function-calls.sh [output.json] [test-type]

DB_URL="${DATABASE_URL:-postgres://cipherstash:password@localhost:7432/postgres}"
OUTPUT="${1:-function-calls.json}"
TEST_TYPE="${2:-unknown}"

# Query PostgreSQL for function call stats
psql "$DB_URL" -t -A -F',' <<'SQL' | jq -R 'split(",") | {schema: .[0], function: .[1], calls: (.[2] | tonumber)}' | jq -s '{test_type: env.TEST_TYPE, timestamp: now | todate, functions: .}' > "$OUTPUT"
SELECT
  n.nspname as schema,
  p.proname as function,
  ps.calls
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
LEFT JOIN pg_stat_user_functions ps ON p.oid = ps.funcid
WHERE n.nspname = 'eql_v2'
  AND ps.calls > 0
ORDER BY ps.calls DESC;
SQL

# Validate output was created
if [ ! -s "$OUTPUT" ]; then
    echo "❌ Error: No function calls tracked. Did tests run?"
    echo "   Make sure to run tests before tracking function calls."
    exit 1
fi

# Verify JSON is valid
if ! jq empty "$OUTPUT" 2>/dev/null; then
    echo "❌ Error: Invalid JSON output"
    exit 1
fi

echo "✅ Function calls tracked: $OUTPUT"
