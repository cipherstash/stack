#!/usr/bin/env bash
#MISE description="Source-only SQL doc validation (coverage + required tags, no DB)"
# Build first so generated encrypted-domain SQL exists under src/.
#MISE depends=["build"]
#
# This is the DB-free subset of `docs:validate`: coverage + required-tags read
# the `--!` doxygen comments out of src/**/*.sql and need no Postgres. It exists
# so CI can validate documentation on EVERY PR (including docs-only PRs that skip
# the heavy, relevance-gated jobs) without standing up a database. The
# `documented-sql` syntax check (which needs psql) stays in the per-Postgres
# `validate` job.

set -e

echo
echo "Checking documentation coverage..."
mise run --output prefix docs:validate:coverage

echo
echo "Validating required tags..."
mise run --output prefix docs:validate:required-tags
