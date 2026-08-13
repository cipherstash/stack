#!/usr/bin/env bash
#MISE description="Validate SQL documentation"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]

set -e

echo
echo "Checking documentation coverage..."
mise run --output prefix docs:validate:coverage

echo
echo "Validating required tags..."
mise run --output prefix docs:validate:required-tags

echo
echo "Validating SQL in documentation..."
mise run --output prefix docs:validate:documented-sql
