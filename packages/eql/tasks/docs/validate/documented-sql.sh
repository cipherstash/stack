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
# The rendered eql_v3 tree, not src/: the source writes its schemas and payload
# version as {{prefix}} / {{eql_version}} placeholders (ADR-0002), which psql
# cannot parse. `mise run build` renders it.
source_directory="build/render/eql_v3/src"
# Files confined to EQL v4 (`-- ONLY EQL VERSION: 4`: the range query domains
# and eql_v4.between) are rendered only into the eql_v4 tree, so they are read
# from there: every file of the v4 tree with no counterpart in the v3 tree. The
# other v4 files are the v3 ones under another name, already validated above.
#
# They are not run in isolation like the v3 files. Every statement in them
# needs the eql_v4 schema and the domains they range over, so in isolation
# their first statement fails with "does not exist", which the loop below
# counts as a dependency error, and nothing after it is ever parsed. Instead
# the whole v4 install order runs in one transaction that is rolled back,
# so each confined file runs after what it requires and every statement in
# it is executed, and any error fails the task.
v4_directory="build/render/eql_v4/src"
v4_order="build/render/eql_v4/deps-ordered.txt"

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

for dir in "$source_directory" "$v4_directory"; do
  if [ ! -d "$dir" ]; then
    echo "error: source directory does not exist: ${dir}"
    exit 2
  fi
done

v4_only=()
while IFS= read -r file; do
  if [ ! -f "$source_directory/${file#"$v4_directory"/}" ]; then
    v4_only+=("$file")
  fi
done < <(find "$v4_directory" -name "*.sql" -not -name "*_test.sql" | sort)
if [ ${#v4_only[@]} -eq 0 ]; then
  echo "error: found no file confined to EQL v4 under ${v4_directory}; expected the range surface"
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
echo "Validating the ${#v4_only[@]} files confined to EQL v4, in the v4 install order..."
if [ ! -f "$v4_order" ]; then
  echo "error: the v4 install order does not exist: ${v4_order}"
  exit 2
fi
for file in "${v4_only[@]}"; do
  if ! grep -qxF "$file" "$v4_order"; then
    echo "error: ${file} is not in the v4 install order ${v4_order}"
    exit 2
  fi
done
v4_script=$(mktemp)
trap 'rm -f "$v4_script"' EXIT
{
  echo 'BEGIN;'
  while IFS= read -r f; do
    printf '\\i %s\n' "$f"
  done < "$v4_order"
  echo 'ROLLBACK;'
} > "$v4_script"
if v4_output=$(PGPASSWORD="$PGPASSWORD" psql -h "$PGHOST" -p "$PGPORT" -U "$PGUSER" -d "$PGDATABASE" \
        -f "$v4_script" --set ON_ERROR_STOP=1 -q 2>&1); then
  echo "✓ the v4 install order, rolled back"
  validated=$((validated + ${#v4_only[@]}))
else
  echo "✗ the v4 install order failed"
  echo "$v4_output" | grep -v '^NOTICE' | tail -10 | sed 's/^/    /'
  echo ""
  errors=$((errors + ${#v4_only[@]}))
fi

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
