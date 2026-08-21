#!/usr/bin/env bash
#MISE description="Validates required Doxygen tags are present"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]

set -e

echo "Validating required Doxygen tags..."
echo ""

source_directory="src"
errors=0
warnings=0

if [ ! -d $source_directory ]; then
  echo "error: source directory does not exist: ${source_directory}"
  exit 2
fi

for file in $(find $source_directory -name "*.sql" -not -name "*_test.sql"); do
  # Skip auto-generated files
  if grep -q "^-- AUTOMATICALLY GENERATED FILE" "$file" 2>/dev/null; then
    continue
  fi

  # For each CREATE FUNCTION, check tags
  functions=$(grep -n "^CREATE FUNCTION" "$file" 2>/dev/null | cut -d: -f1 || echo "")

  for line_no in $functions; do
    # Find comment block above function (search backwards max 50 lines)
    start=$((line_no - 50))
    [ "$start" -lt 1 ] && start=1

    comment_block=$(sed -n "${start},${line_no}p" "$file" | grep "^--!" | tail -100)

    function_sig=$(sed -n "${line_no}p" "$file")
    # Extract function name (compatible with BSD sed/grep)
    function_name=$(echo "$function_sig" | sed -n 's/^CREATE FUNCTION[[:space:]]*\([^(]*\).*/\1/p' | xargs || echo "unknown")

    # Check for @brief
    if ! echo "$comment_block" | grep -q "@brief"; then
      echo "ERROR: $file:$line_no $function_name - Missing @brief"
      errors=$((errors + 1))
    fi

    # Check for @param (if function has parameters)
    if echo "$function_sig" | grep -q "(" && \
       ! echo "$function_sig" | grep -q "()"; then
      if ! echo "$comment_block" | grep -q "@param"; then
        echo "WARNING: $file:$line_no $function_name - Missing @param"
        warnings=$((warnings + 1))
      fi
    fi

    # Check for @return (if function returns something other than void)
    if ! echo "$function_sig" | grep -qi "RETURNS void"; then
      if ! echo "$comment_block" | grep -q "@return"; then
        echo "ERROR: $file:$line_no $function_name - Missing @return"
        errors=$((errors + 1))
      fi
    fi
  done
done

# Also check template files
for file in $(find $source_directory -name "*.template"); do
  functions=$(grep -n "^CREATE FUNCTION" "$file" 2>/dev/null | cut -d: -f1 || echo "")

  for line_no in $functions; do
    start=$((line_no - 50))
    [ "$start" -lt 1 ] && start=1

    comment_block=$(sed -n "${start},${line_no}p" "$file" | grep "^--!" | tail -100)

    function_sig=$(sed -n "${line_no}p" "$file")
    # Extract function name (compatible with BSD sed/grep)
    function_name=$(echo "$function_sig" | sed -n 's/^CREATE FUNCTION[[:space:]]*\([^(]*\).*/\1/p' | xargs || echo "unknown")

    if ! echo "$comment_block" | grep -q "@brief"; then
      echo "ERROR: $file:$line_no $function_name - Missing @brief"
      errors=$((errors + 1))
    fi

    if echo "$function_sig" | grep -q "(" && \
       ! echo "$function_sig" | grep -q "()"; then
      if ! echo "$comment_block" | grep -q "@param"; then
        echo "WARNING: $file:$line_no $function_name - Missing @param"
        warnings=$((warnings + 1))
      fi
    fi

    if ! echo "$function_sig" | grep -qi "RETURNS void"; then
      if ! echo "$comment_block" | grep -q "@return"; then
        echo "ERROR: $file:$line_no $function_name - Missing @return"
        errors=$((errors + 1))
      fi
    fi
  done
done

echo ""
echo "Validation summary:"
echo "  Errors: $errors"
echo "  Warnings: $warnings"
echo ""

if [ "$errors" -gt 0 ]; then
  echo "❌ Validation failed with $errors errors"
  exit 1
else
  echo "✅ All required tags present"
  exit 0
fi
