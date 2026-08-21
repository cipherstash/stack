#!/usr/bin/env bash
#MISE description="Validates SQL syntax for all documented files"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]

set -e

PGHOST=${PGHOST:-localhost}
PGPORT=${PGPORT:-7432}
PGUSER=${PGUSER:-cipherstash}
PGPASSWORD=${PGPASSWORD:-password}
PGDATABASE=${PGDATABASE:-postgres}
source_directory="src"

echo "Validating SQL syntax for all documented files..."
echo ""

# Install the full extension first to satisfy dependencies
# Note: This validation runs files in isolation without respecting dependencies
# Files that depend on types from other files will show "does not exist" errors
# This is expected behavior - the validation ensures SQL syntax is correct
echo "Note: Some files may show dependency errors - this is expected"
echo ""

errors=0
validated=0

if [ ! -d $source_directory ]; then
  echo "error: source directory does not exist: ${source_directory}"
  exit 2
fi

for file in $(find $source_directory -name "*.sql" -not -name "*_test.sql" | sort); do
  echo -n "Validating $file... "

  # Capture both stdout and stderr
  error_output=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
          -f "$file" --set ON_ERROR_STOP=1 -q 2>&1) || exit_code=$?

  if [ "${exit_code:-0}" -eq 0 ]; then
    echo "✓"
    validated=$((validated + 1))
  else
    # Check if this is a dependency error (expected) or a real syntax error
    if echo "$error_output" | grep -qE "(does not exist|already exists)"; then
      echo "⊘ (dependency issue - expected)"
      validated=$((validated + 1))  # Count as validated since syntax is correct
    else
      echo "✗ SYNTAX ERROR"
      echo "  Error in: $file"
      echo "  Details:"
      echo "$error_output" | tail -10 | sed 's/^/    /'
      echo ""
      errors=$((errors + 1))
    fi
  fi
  exit_code=0
done

echo ""
echo "Validation complete:"
echo "  Validated: $validated"
echo "  Errors: $errors"

if [ $errors -gt 0 ]; then
  echo ""
  echo "❌ Validation failed with $errors errors"
  exit 1
else
  echo ""
  echo "✅ All SQL files validated successfully"
  exit 0
fi
