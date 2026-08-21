#!/usr/bin/env bash
#MISE description="Checks documentation coverage for SQL files"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]

set -e

echo "# SQL Documentation Coverage Report"
echo ""
echo "Generated: $(date +"%Y-%m-%dT%H:%M:%S%z")"
echo ""

source_directory="src"
total_sql_files=0
documented_sql_files=0

if [ ! -d $source_directory ]; then
  echo "error: source directory does not exist: ${source_directory}"
  exit 2
fi

# Check .sql files
for file in $(find $source_directory -name "*.sql" -not -name "*_test.sql" | sort); do
  # Skip auto-generated files
  if grep -q "^-- AUTOMATICALLY GENERATED FILE" "$file" 2>/dev/null; then
    echo "- $file: ⊘ Auto-generated (skipped)"
    continue
  fi

  total_sql_files=$((total_sql_files + 1))

  if grep -q "^--! @brief" "$file" 2>/dev/null; then
    echo "- $file: ✓ Documented"
    documented_sql_files=$((documented_sql_files + 1))
  else
    echo "- $file: ✗ No documentation"
  fi
done

# Check .template files
total_template_files=0
documented_template_files=0

for file in $(find $source_directory -name "*.template" | sort); do
  total_template_files=$((total_template_files + 1))

  if grep -q "^--! @brief" "$file" 2>/dev/null; then
    echo "- $file: ✓ Documented"
    documented_template_files=$((documented_template_files + 1))
  else
    echo "- $file: ✗ No documentation"
  fi
done

total_files=$((total_sql_files + total_template_files))
documented_files=$((documented_sql_files + documented_template_files))

echo ""
echo "## Summary"
echo ""
echo "- SQL files: $documented_sql_files/$total_sql_files"
echo "- Template files: $documented_template_files/$total_template_files"
echo "- Total files: $documented_files/$total_files"

if [ $total_files -gt 0 ]; then
  coverage=$((documented_files * 100 / total_files))
  echo "- Coverage: ${coverage}%"
else
  coverage=0
fi

echo ""

if [ $coverage -eq 100 ]; then
  echo "✅ 100% documentation coverage achieved!"
  exit 0
else
  echo "⚠️  Documentation coverage: ${coverage}%"
  exit 1
fi
